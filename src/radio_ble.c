#include "radio_ble.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net_buf.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/buf.h>
#include <zephyr/bluetooth/hci_raw.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/logging/log.h>

/* For SN_BATCH_LINGER_MS: both radios linger the same, so a capture does
 * not change character when the radio does. */
#include "batch.h"
#include "frame.h"
#include "link.h"

/* H4 packet type for an HCI event. In raw mode the type is a property of the
 * net_buf rather than a byte inside it, so it is put back on the front here --
 * the host's dissector expects H4 framing, starting with this byte. */
#define H4_EVENT 0x04u
/* Isochronous data is simply another H4 packet type, which is the reason this
 * needed no new frame type: the BLE path already carries whatever H4 packet
 * the controller hands over, and Wireshark's own HCI dissector reads ISO. */
#define H4_ISO   0x05u

/* Scan parameters, assembled exactly as the ESP32-C6 firmware assembles them
 * so the two controllers are told the same thing. */
/* RANDOM, not public, and this is the difference between capturing and not.
 *
 * nRF parts ship with no public Bluetooth address. Asking to scan with
 * own_addr_type = 0x00 is accepted by LE Set Extended Scan Parameters and then
 * refused by LE Set Extended Scan Enable with 0x12, Invalid HCI Command
 * Parameters -- the rejection names neither the address nor the parameter that
 * caused it. The ESP32-C6 uses public because it has one burned in.
 *
 * The address below is never transmitted. A passive scanner sends no scan
 * requests, so it never puts an address on air; the controller merely insists
 * on having a valid one before it will start. The top two bits are set, which
 * is what makes it a static random address rather than a resolvable one. */
#define OWN_ADDR_RANDOM   0x01u
#define FILTER_ACCEPT_ALL  0x00u
#define FILTER_ACCEPT_LIST 0x01u
#define SCAN_TYPE_PASSIVE 0x00u   /* never transmit; the whole point */

/* HCI uses 0.625 ms units for scan interval and window. */
#define UNITS_PER_MS(ms) ((uint16_t)(((uint32_t)(ms) * 1000u) / 625u))

static int apply_filter(void);
static void note_periodic(const uint8_t *hci, uint16_t len);
static void note_biginfo(const uint8_t *hci, uint16_t len);

LOG_MODULE_REGISTER(radio_ble, LOG_LEVEL_INF);

static K_FIFO_DEFINE(hci_rx);
static bool running;
static uint32_t captured;

/* The command in flight and what the controller said about it. One at a
 * time: the lock serialises the control path against the sync workers. */
static K_MUTEX_DEFINE(cmd_lock);
static K_SEM_DEFINE(cmd_done, 0, 1);
static volatile uint16_t pending_opcode;
static volatile uint8_t pending_status;

/* Eight is what the host's dialog allows and what the ESP32-C6 stores. */
#define MAX_FILTER 8
#define FILTER_ENTRY 7   /* address type, then six bytes of address */
static uint8_t filter[MAX_FILTER][FILTER_ENTRY];
static uint8_t filter_count;

/* Identity resolving keys: N x (identity type, identity address, key), both
 * least significant first, exactly as the host frames them. Held for one
 * capture, cleared when it stops, never logged. */
#define KEY_ENTRY 23u
#define MAX_KEYS CONFIG_BT_CTLR_RL_SIZE
static uint8_t keys[MAX_KEYS][KEY_ENTRY];
static uint8_t key_count;

/* Periodic advertising. This is the count the SoftDevice Controller is
 * configured for, and it is one: NCS's hci_driver sets
 * SDC_PERIODIC_ADV_SYNC_COUNT from CONFIG_BT_PER_ADV_SYNC_MAX, which defaults
 * to 1, and prj.conf does not set it. Asking for a second sync only produces
 * a refusal, and a refusal leaves the count where it was -- so every later
 * repeat of that train's advertisement asks again. If this ever needs to be
 * two, raise CONFIG_BT_PER_ADV_SYNC_MAX first. */
#define MAX_SYNCS 1
static bool periodic_enabled;
static uint8_t sync_count;

/* One broadcast group at a time. A second would need its own BIG handle and
 * its own set of stream indices, and nothing here has asked for two. */
#define MAX_BIS 4
static bool big_synced;

struct sync_req {
	uint8_t sid;
	uint8_t addr_type;
	uint8_t addr[6];
};

/* Requests are handed to a work item rather than issued where the
 * advertisement is seen: that runs on the thread draining HCI events, and a
 * command there would stall forwarding for as long as the controller took to
 * answer. Four deep because every repeat of an advertisement queues another
 * request until the sync is established. */
K_MSGQ_DEFINE(sync_q, sizeof(struct sync_req), 4, 4);
static void sync_work_fn(struct k_work *work);
static K_WORK_DEFINE(sync_work, sync_work_fn);

/* Counters for the STATS frame, in sn_ble_stats order. These used to be two
 * accessors nothing called, so a BLE capture on this board reported the
 * 802.15.4 counters of a stopped radio -- zero drops, whatever happened. */
static uint32_t adv_reports;
static uint32_t forwarded;
static uint32_t oversized;
static uint32_t dropped;
static uint32_t periodic_seen;
static uint32_t periodic_synced;
static uint32_t periodic_reports;
static uint32_t periodic_refused;

/* The forwarding thread. Its own stack rather than the system work queue's:
 * an extended advertising report is up to 300 bytes and is copied here, and
 * this board has one thread stack that must not be grown -- see
 * docs/2026-09-14-nrf54l15-spike.md -- so it is kept well away from that. */
#define FWD_STACK_SIZE 2048
#define FWD_PRIORITY   7
static K_THREAD_STACK_DEFINE(fwd_stack, FWD_STACK_SIZE);
static struct k_thread fwd_thread;

/* Staging for one forwarded packet: metadata, the H4 type byte, the event. */
static uint8_t out[sizeof(struct sn_ble_meta) + SN_BLE_MAX_PACKET];

/* Batching, for the same reason the 802.15.4 path has it: a BLE packet sent
 * alone costs 22 bytes of overhead against a 94 kB/s link.
 *
 * Bounded by BYTES rather than by the worst case in entries. Thirty-two
 * maximum-length HCI events would need nearly 10 KB of buffer for a case that
 * does not occur -- advertising reports here run 47 to 60 bytes -- so this
 * holds about thirty typical ones and closes early if they are large. */
#define BLE_BATCH_BUF      2048
#define BLE_MAX_ENTRIES    32
#define BLE_BATCH_HDR_LEN  9   /* u64 base timestamp, u8 count */
/* u16 dt, u16 orig_len, u8 flags, u16 len.
 *
 * The length is sixteen bits because an HCI event does not fit in eight: its
 * own parameter-length field is a byte, so the H4 packet reaches 258 -- a type
 * byte, a two-byte header and 255 of parameters. An eight-bit field wrapped
 * modulo 256 and the host lost alignment part-way through a batch, reporting
 * trailing bytes and naming nothing that pointed at the length. */
#define BLE_ENTRY_LEN      7

static uint8_t bbuf[BLE_BATCH_BUF];
static size_t bused = BLE_BATCH_HDR_LEN;
static uint8_t bcount;
static uint64_t bbase_us;
static uint64_t blast_us;
static K_MUTEX_DEFINE(block);
static void ble_linger_expired(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(ble_linger, ble_linger_expired);

static uint64_t now_us(void)
{
	/* Arrival at this firmware, not at the antenna: the controller does
	 * not expose a radio timestamp over HCI. Honest about being that,
	 * exactly as the C6's esp_timer reading is. */
	return k_ticks_to_us_floor64(k_uptime_ticks());
}

/* Picks the answer to our own command out of the event stream. Command
 * Complete puts the opcode at 3 and the status at 5; Command Status puts the
 * status at 2 and the opcode at 4. */
static void note_command_result(const uint8_t *evt, uint16_t len)
{
	uint16_t opcode;
	uint8_t status;

	if (evt[0] == BT_HCI_EVT_CMD_COMPLETE && len >= 6u) {
		opcode = sys_get_le16(evt + 3);
		status = evt[5];
	} else if (evt[0] == BT_HCI_EVT_CMD_STATUS && len >= 6u) {
		status = evt[2];
		opcode = sys_get_le16(evt + 4);
	} else {
		return;
	}
	if (opcode == 0u || opcode != pending_opcode) {
		return;
	}
	pending_status = status;
	pending_opcode = 0u;
	k_sem_give(&cmd_done);
}

/* Sends one HCI command and waits for the controller's answer to it:
 * 0 accepted, -EIO refused (its status in *status if given), -ETIMEDOUT no
 * answer, or bt_send()'s own error. Does not log a refusal -- for a caller
 * like the sync worker a refusal is ordinary.
 *
 * This used to send, sleep 20 ms and return bt_send()'s result, which says
 * only that the buffer was queued. A command the controller REFUSED was
 * never noticed: a scan with an impossible PHY bitmap started "fine" and
 * captured nothing -- measured, 0 advertising reports in 8 s against 243.
 * Waiting for the answer also replaces the sleep that kept us inside one
 * outstanding command.
 *
 * Never call this from the forwarding thread: that thread delivers the
 * answer, so it would wait for itself. */
static int hci_command(uint16_t opcode, const uint8_t *params, uint8_t len,
		       uint8_t *status)
{
	k_mutex_lock(&cmd_lock, K_FOREVER);

	struct net_buf *buf = bt_buf_get_tx(BT_BUF_CMD, K_SECONDS(1), NULL, 0);

	if (buf == NULL) {
		k_mutex_unlock(&cmd_lock);
		return -ENOBUFS;
	}

	/* The command header goes in the buffer; only the H4 type byte is
	 * carried out of band, as the buffer's type. */
	struct bt_hci_cmd_hdr *hdr = net_buf_add(buf, sizeof(*hdr));

	hdr->opcode = sys_cpu_to_le16(opcode);
	hdr->param_len = len;
	if (len > 0u) {
		net_buf_add_mem(buf, params, len);
	}

	k_sem_reset(&cmd_done);
	pending_status = 0xFFu;
	pending_opcode = opcode;

	int err = bt_send(buf);

	if (err == 0 && k_sem_take(&cmd_done, K_SECONDS(2)) != 0) {
		LOG_ERR("HCI opcode 0x%04x never completed", opcode);
		err = -ETIMEDOUT;
	} else if (err == 0 && pending_status != 0u) {
		err = -EIO;
	}
	if (status != NULL) {
		*status = pending_status;
	}
	pending_opcode = 0u;
	k_mutex_unlock(&cmd_lock);
	return err;
}

/* hci_command(), with a refusal logged: during setup every refusal is a
 * fault somebody needs to see. */
static int send_command(uint16_t opcode, const uint8_t *params, uint8_t len)
{
	uint8_t status = 0u;
	const int err = hci_command(opcode, params, len, &status);

	if (err == -EIO) {
		LOG_ERR("HCI opcode 0x%04x refused, status 0x%02x", opcode,
			status);
	}
	return err;
}

/* Sends one packet on its own. The caller holds the lock. */
static void send_alone(uint64_t timestamp_us, uint16_t orig_len, uint8_t flags,
		       const uint8_t *hci, uint16_t len)
{
	const struct sn_ble_meta meta = {
		.timestamp_us = timestamp_us,
		.orig_len = orig_len,
		.flags = flags,
		.reserved = 0u,
	};

	memcpy(out, &meta, sizeof(meta));
	memcpy(out + sizeof(meta), hci, len);

	if (sn_link_send(SN_FRAME_PACKET, out, sizeof(meta) + len) != 0) {
		dropped++;
	} else {
		forwarded++;
	}
}

/* Sends the open batch. The caller holds the lock. */
static void ble_flush_locked(void)
{
	if (bcount == 0u) {
		return;
	}

	/* A batch of one is sent as a PACKET, because as a batch it would be
	 * BIGGER: 10 bytes of frame header, 9 of batch header and a 6-byte
	 * entry is 25, against 22 for a PACKET and its metadata. The same
	 * arithmetic as the 802.15.4 path, and the same reason -- on a quiet
	 * channel most batches close with one packet in them. */
	if (bcount == 1u) {
		const uint8_t *entry = bbuf + BLE_BATCH_HDR_LEN;
		const uint16_t orig_len =
			(uint16_t)(entry[2] | ((uint16_t)entry[3] << 8));
		const uint16_t len =
			(uint16_t)(entry[5] | ((uint16_t)entry[6] << 8));

		send_alone(bbase_us, orig_len, entry[4],
			   entry + BLE_ENTRY_LEN, len);
		bcount = 0u;
		bused = BLE_BATCH_HDR_LEN;
		return;
	}

	for (int i = 0; i < 8; i++) {
		bbuf[i] = (uint8_t)(bbase_us >> (8 * i));
	}
	bbuf[8] = bcount;

	/* Counted in packets, not frames: a refused batch is every packet in
	 * it, and reporting one drop would understate the loss. */
	if (sn_link_send(SN_FRAME_BLE_BATCH, bbuf, bused) != 0) {
		dropped += bcount;
	} else {
		forwarded += bcount;
	}

	bcount = 0u;
	bused = BLE_BATCH_HDR_LEN;
}

static void ble_linger_expired(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&block, K_FOREVER);
	ble_flush_locked();
	k_mutex_unlock(&block);
}

/* Counts what an event was, for the STATS frame.
 *
 * Read straight off the event rather than the H4-shimmed copy note_periodic
 * works on, so every offset here is one lower than there: evt[0] is the event
 * code and evt[2] the LE subevent. */
static void note_counts(const uint8_t *evt, uint16_t len)
{
	if (len < 3u || evt[0] != BT_HCI_EVT_LE_META_EVENT) {
		return;
	}

	switch (evt[2]) {
	case BT_HCI_EVT_LE_ADVERTISING_REPORT:
	case BT_HCI_EVT_LE_EXT_ADVERTISING_REPORT:
		adv_reports++;
		break;
	/* Both versions of both events. This controller sends only v2 --
	 * measured following a train at 80 ms: one 0x24 and 365 0x25 in 30 s,
	 * and not a single v1 -- so counting v1 alone reported every periodic
	 * figure as zero while the train was being followed perfectly well.
	 * Status leads in both versions, so one check serves. */
	case BT_HCI_EVT_LE_PER_ADVERTISING_REPORT:
	case BT_HCI_EVT_LE_PER_ADVERTISING_REPORT_V2:
		periodic_reports++;
		break;
	case BT_HCI_EVT_LE_PER_ADV_SYNC_ESTABLISHED:
	case BT_HCI_EVT_LE_PER_ADV_SYNC_ESTABLISHED_V2:
		/* Its first parameter is a status, so this one event is both
		 * the success and the failure report -- and the failure is the
		 * only place a refusal can be seen here, because send_command
		 * waits for nothing and returns whether the command was
		 * handed over, not whether it was accepted.
		 *
		 * Freeing the slot is the part that matters more than the
		 * counter: sync_count went up when the command went out, and
		 * with one sync to give, a failure that left it up would stop
		 * this board following any train for the rest of the
		 * capture. */
		if (len >= 4u && evt[3] == BT_HCI_ERR_SUCCESS) {
			periodic_synced++;
		} else {
			periodic_refused++;
			if (sync_count > 0u) {
				sync_count--;
			}
		}
		break;
	case BT_HCI_EVT_LE_PER_ADV_SYNC_LOST:
		/* The train went away. Same reasoning: hold the slot and
		 * nothing replaces it. */
		if (sync_count > 0u) {
			sync_count--;
		}
		break;
	default:
		break;
	}
}

static void forward(struct net_buf *buf, uint8_t h4_type)
{
	/* One more byte than the event, for the H4 type put back on the
	 * front. The host counts orig_len the same way. */
	const uint16_t full = (uint16_t)(buf->len + 1u);
	uint16_t take = full;
	uint8_t flags = 0u;

	if (take > SN_BLE_MAX_PACKET) {
		take = SN_BLE_MAX_PACKET;
		flags |= SN_BLE_FLAG_TRUNCATED;
		oversized++;
	}

	const uint64_t ts = now_us();

	/* Unconditional, unlike the periodic peek below: how many of these
	 * were advertising reports is the difference between an empty room
	 * and a deaf radio, and both are worth knowing when periodic
	 * following is off. */
	if (h4_type == H4_EVENT) {
		note_counts(buf->data, buf->len);
	}

	/* Before batching, because this reads the event rather than the copy,
	 * and because a train noticed late is a train not followed. */
	if (periodic_enabled) {
		/* The H4 byte is not in the buffer, so a one-byte shim keeps
		 * the offsets the same as everywhere else that reads an HCI
		 * packet. */
		static uint8_t peek[32];
		const uint16_t n = buf->len + 1u > sizeof(peek)
				 ? (uint16_t)sizeof(peek)
				 : (uint16_t)(buf->len + 1u);

		peek[0] = H4_EVENT;
		memcpy(peek + 1, buf->data, n - 1u);
		note_periodic(peek, n);
		note_biginfo(peek, n);
	}

	k_mutex_lock(&block, K_FOREVER);

	/* Close the open batch if this packet cannot join it: a delta too wide
	 * for sixteen bits, a clock that went backwards, or not enough room
	 * left. All three are conditions the host would refuse the frame for. */
	if (bcount > 0u &&
	    (ts < blast_us || ts - blast_us > 0xFFFFu ||
	     bused + BLE_ENTRY_LEN + take > sizeof(bbuf))) {
		ble_flush_locked();
	}

	if (bcount == 0u) {
		bbase_us = ts;
		blast_us = ts;
	}

	const uint16_t dt = (uint16_t)(ts - blast_us);
	uint8_t *at = bbuf + bused;

	at[0] = (uint8_t)(dt & 0xFFu);
	at[1] = (uint8_t)(dt >> 8);
	at[2] = (uint8_t)(full & 0xFFu);
	at[3] = (uint8_t)(full >> 8);
	at[4] = flags;
	at[5] = (uint8_t)(take & 0xFFu);
	at[6] = (uint8_t)(take >> 8);
	/* The H4 type byte is not in the buffer in raw mode, so it goes back
	 * on the front here -- the host's dissector expects H4 framing. */
	at[BLE_ENTRY_LEN] = h4_type;
	memcpy(at + BLE_ENTRY_LEN + 1, buf->data, take - 1u);

	bused += BLE_ENTRY_LEN + take;
	blast_us = ts;
	bcount++;
	captured++;

	if (bcount == BLE_MAX_ENTRIES) {
		ble_flush_locked();
		(void)k_work_cancel_delayable(&ble_linger);
	} else {
		/* Rescheduled per packet, so the timer measures silence rather
		 * than the age of the batch. */
		(void)k_work_reschedule(&ble_linger,
					K_MSEC(SN_BATCH_LINGER_MS));
	}

	k_mutex_unlock(&block);
}

static void fwd_loop(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	while (true) {
		struct net_buf *buf = k_fifo_get(&hci_rx, K_FOREVER);

		if (buf == NULL) {
			continue;
		}

		/* Only events, only once scanning has been enabled, and never
		 * the controller's answers to our own commands.
		 *
		 * The `running` flag alone is not enough. It is set after the
		 * scan-enable command is sent, and that command's own Command
		 * Complete arrives asynchronously afterwards -- so it raced
		 * past the flag and appeared as frame 1 of a capture. Dropping
		 * the two reply events by code does not depend on timing.
		 *
		 * A capture should contain what the radio heard. Nothing else
		 * is lost: an advertisement arrives as an LE Meta event.
		 *
		 * The packet type is the buffer's H:4 prefix, read directly.
		 * This used bt_buf_get_type(), now deprecated, which pulls the
		 * same byte but assumes the buffer is OUTGOING: an incoming ISO
		 * packet came back as BT_BUF_ISO_OUT, the BT_BUF_ISO_IN test
		 * below could never match, and no broadcast audio reached a
		 * capture however well the BIG was followed. */
		const uint8_t h4 = net_buf_pull_u8(buf);

		/* Our own commands' answers, before the capture filter below
		 * drops them: send_command() is waiting on one. */
		if (h4 == BT_HCI_H4_EVT && buf->len >= 2u) {
			note_command_result(buf->data, buf->len);
		}

		if (running && h4 == BT_HCI_H4_ISO) {
			/* A broadcast isochronous stream: the audio itself,
			 * rather than the advertisement announcing it. */
			forward(buf, H4_ISO);
		} else if (running && h4 == BT_HCI_H4_EVT && buf->len > 0u &&
			   buf->data[0] != BT_HCI_EVT_CMD_COMPLETE &&
			   buf->data[0] != BT_HCI_EVT_CMD_STATUS) {
			forward(buf, H4_EVENT);
		}

		net_buf_unref(buf);
	}
}

int sn_radio_ble_init(void)
{
	const int err = bt_enable_raw(&hci_rx);

	if (err != 0) {
		return err;
	}

	k_thread_create(&fwd_thread, fwd_stack, FWD_STACK_SIZE,
			fwd_loop, NULL, NULL, NULL,
			FWD_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&fwd_thread, "ble_fwd");
	return 0;
}

int sn_radio_ble_start(uint16_t interval_ms, uint16_t window_ms, uint8_t phys)
{
	if (phys == 0u) {
		/* Zero would tell the controller to scan on no PHY at all,
		 * which it accepts and which captures nothing. Refused rather
		 * than corrected, so a host asking for something impossible
		 * hears about it. */
		return -EINVAL;
	}
	/* Defaulted and clamped rather than rejected, because the ESP32-C6
	 * firmware does exactly this and two boards disagreeing about what an
	 * odd request means would be worse than either answer. A window equal
	 * to the interval is continuous scanning, which is what a sniffer
	 * wants. */
	if (interval_ms == 0u) {
		interval_ms = SN_BLE_DEFAULT_INTERVAL_MS;
	}
	if (window_ms == 0u || window_ms > interval_ms) {
		window_ms = interval_ms;
	}

	/* Reset, then unmask the events that carry advertisements.
	 *
	 * Without the two masks the controller accepts every command happily
	 * and reports not one advertisement, because LE Meta is masked off by
	 * default and the extended advertising report subevent is masked off
	 * within it. The ESP32-C6 firmware learned this the same way; its
	 * comment says so, and this is the same sequence.
	 *
	 * The reset comes first because it clears the masks, so setting them
	 * before it would achieve nothing. */
	static const uint8_t all_events[8] = {
		0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0x3Fu};
	static const uint8_t all_le_events[8] = {
		0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu};

	/* Set after the reset, which clears it, and before the scan parameters
	 * that refer to it. */
	static const uint8_t static_random_addr[6] = {
		0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0xC0u};

	int err = send_command(BT_HCI_OP_RESET, NULL, 0);

	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_SET_EVENT_MASK,
			   all_events, sizeof(all_events));
	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_LE_SET_EVENT_MASK,
			   all_le_events, sizeof(all_le_events));
	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_LE_SET_RANDOM_ADDRESS,
			   static_random_addr, sizeof(static_random_addr));
	if (err != 0) {
		return err;
	}
	/* After the reset, which clears the controller's list, and before the
	 * scan parameters, which name the policy referring to it. */
	err = apply_filter();
	if (err != 0) {
		return err;
	}

	const uint16_t interval = UNITS_PER_MS(interval_ms);
	const uint16_t window = UNITS_PER_MS(window_ms);

	uint8_t params[3 + 8 * 5];
	uint8_t n = 0;

	params[n++] = OWN_ADDR_RANDOM;
	/* Set from whether any addresses were given, so a filter that was
	 * asked for and silently not applied cannot happen. */
	params[n++] = filter_count > 0u ? FILTER_ACCEPT_LIST
				        : FILTER_ACCEPT_ALL;
	params[n++] = phys;
	for (uint8_t bit = 0; bit < 8; bit++) {
		if ((phys & (1u << bit)) == 0u) {
			continue;
		}
		params[n++] = SCAN_TYPE_PASSIVE;
		params[n++] = (uint8_t)(interval & 0xFFu);
		params[n++] = (uint8_t)(interval >> 8);
		params[n++] = (uint8_t)(window & 0xFFu);
		params[n++] = (uint8_t)(window >> 8);
	}

	err = send_command(BT_HCI_OP_LE_SET_EXT_SCAN_PARAM, params, n);
	if (err != 0) {
		return err;
	}

	/* Enable, no duplicate filtering, no duration or period limit. A
	 * sniffer wants every repeat of an advertisement, not the first. */
	const uint8_t enable[6] = {0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};

	err = send_command(BT_HCI_OP_LE_SET_EXT_SCAN_ENABLE,
			   enable, sizeof(enable));
	if (err != 0) {
		return err;
	}

	/* A fresh scan is a fresh controller: the reset above dropped any
	 * syncs it held, so the count has to follow it down or no new train
	 * would ever be followed. */
	sync_count = 0u;
	big_synced = false;
	k_msgq_purge(&sync_q);

	/* Set last: everything above is configuration, and forwarding it
	 * would put our own command completes in the capture. */
	running = true;
	return 0;
}

void sn_radio_ble_set_periodic(bool enable)
{
	periodic_enabled = enable;
}

static void sync_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	struct sync_req req;

	while (k_msgq_get(&sync_q, &req, K_NO_WAIT) == 0) {
		if (!periodic_enabled || sync_count >= MAX_SYNCS) {
			continue;
		}

		/* options 0: use the address given rather than the
		 * controller's advertiser list, and report from the start.
		 * skip 0, timeout 10 s in 10 ms units, no CTE constraint. */
		uint8_t params[14] = {0};

		params[1] = req.sid;
		params[2] = req.addr_type;
		memcpy(params + 3, req.addr, sizeof(req.addr));
		params[11] = 0xE8u;
		params[12] = 0x03u;

		if (hci_command(BT_HCI_OP_LE_PER_ADV_CREATE_SYNC,
				params, sizeof(params), NULL) == 0) {
			sync_count++;
		}
		/* A refusal is ordinary rather than an error: the controller
		 * rejects a duplicate sync to a train it already follows, and
		 * every repeat of that advertisement queues another request. */
	}
}

/* BIG Create Sync, handed to a work item for the reason sync requests are.
 * note_biginfo() runs on the forwarding thread, which is also the thread
 * that delivers the controller's answer: waiting for it there would wait
 * for itself, time out after two seconds, and never join a broadcast. */
static uint8_t big_params[25 + MAX_BIS];
static uint8_t big_len;
static atomic_t big_pending;
static void big_work_fn(struct k_work *work);
static K_WORK_DEFINE(big_work, big_work_fn);

static void big_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (hci_command(BT_HCI_OP_LE_BIG_CREATE_SYNC, big_params, big_len,
			NULL) == 0) {
		big_synced = true;
	}
	atomic_clear(&big_pending);
}

/* Notices the BIGInfo that a synced periodic train carries, and asks the
 * controller to join the broadcast it describes.
 *
 * BIGInfo is what turns "there is an Auracast broadcast here" into being able
 * to receive it: the periodic train announces the group, and this is the
 * announcement. Everything needed is in the report -- the sync handle it
 * arrived on, and how many streams the group has -- so no state has to be
 * carried from the sync that preceded it. */
static void note_biginfo(const uint8_t *hci, uint16_t len)
{
	/* H4, event code, length, subevent, then sync_handle and num_bis. */
	if (len < 8u || hci[1] != 0x3Eu ||
	    hci[3] != BT_HCI_EVT_LE_BIGINFO_ADV_REPORT) {
		return;
	}
	if (big_synced) {
		return;
	}

	const uint16_t sync_handle = hci[4] | ((uint16_t)hci[5] << 8);
	const uint8_t num_bis = hci[6];

	if (num_bis == 0u || num_bis > MAX_BIS) {
		return;
	}

	/* BIG_Handle, Sync_Handle, Encryption, Broadcast_Code, MSE,
	 * BIG_Sync_Timeout, Num_BIS, then one index per stream.
	 *
	 * Encryption stays zero with an empty broadcast code: an encrypted
	 * broadcast needs a key nobody has given us, and asking to join one
	 * without it fails rather than producing anything. MSE 0 lets the
	 * controller choose; timeout is 2 seconds in 10 ms units. */
	uint8_t params[25 + MAX_BIS] = {0};
	uint8_t n = 0;

	params[n++] = 0u;                       /* BIG handle */
	params[n++] = (uint8_t)(sync_handle & 0xFFu);
	params[n++] = (uint8_t)(sync_handle >> 8);
	params[n++] = 0u;                       /* not encrypted */
	n += 16u;                               /* broadcast code, all zero */
	params[n++] = 0u;                       /* MSE: controller's choice */
	params[n++] = 0xC8u;                    /* timeout 2 s, low byte */
	params[n++] = 0x00u;
	params[n++] = num_bis;
	for (uint8_t i = 0; i < num_bis; i++) {
		params[n++] = i + 1u;           /* BIS indices are 1-based */
	}

	/* One request in flight is enough: every BIGInfo repeats until the
	 * sync is made. */
	if (!atomic_cas(&big_pending, 0, 1)) {
		return;
	}
	memcpy(big_params, params, n);
	big_len = n;
	k_work_submit(&big_work);
}

/* Notices a periodic train in an extended advertising report and asks for a
 * sync. Called with the HCI event, from the forwarding thread. */
static void note_periodic(const uint8_t *hci, uint16_t len)
{
	/* H4, event code, length, subevent, num_reports, then a report whose
	 * periodic interval sits 14 bytes in. Zero means no train. */
	if (len < 21u || hci[1] != 0x3Eu || hci[3] != 0x0Du) {
		return;
	}
	if ((hci[19] | ((uint16_t)hci[20] << 8)) == 0u) {
		return;
	}

	/* Counted per announcement rather than per advertiser: the same train
	 * is announced repeatedly, and the figure is here to show the
	 * detection path ran at all. */
	periodic_seen++;

	struct sync_req req = {
		.sid = hci[16],
		.addr_type = hci[7],
	};

	memcpy(req.addr, hci + 8, sizeof(req.addr));
	if (k_msgq_put(&sync_q, &req, K_NO_WAIT) == 0) {
		k_work_submit(&sync_work);
	}
}

void sn_radio_ble_set_filter(const uint8_t *payload, size_t len)
{
	filter_count = 0u;
	while ((size_t)(filter_count + 1) * FILTER_ENTRY <= len &&
	       filter_count < MAX_FILTER) {
		memcpy(filter[filter_count],
		       payload + (size_t)filter_count * FILTER_ENTRY,
		       FILTER_ENTRY);
		filter_count++;
	}
}

int sn_radio_ble_set_keys(const uint8_t *payload, size_t len)
{
	/* Refused whole rather than truncated: a key silently dropped is a
	 * device silently not followed. */
	if (len % KEY_ENTRY != 0u || len / KEY_ENTRY > MAX_KEYS) {
		LOG_WRN("device keys rejected: %u bytes", (unsigned)len);
		return -EINVAL;
	}
	for (size_t i = 0; i < len; i += KEY_ENTRY) {
		if (payload[i] > 1u) {
			LOG_WRN("device keys rejected: address type %u",
				payload[i]);
			return -EINVAL;
		}
	}
	memset(keys, 0, sizeof(keys));
	memcpy(keys, payload, len);
	key_count = (uint8_t)(len / KEY_ENTRY);
	LOG_INF("device keys: %u", key_count);
	return 0;
}

/* Loads the resolving list: resolution off (the list cannot change while it
 * is on), clear, each key with device privacy mode, then resolution on.
 * Device privacy mode so a listed device advertising under its identity
 * address is still heard; the default drops it. The local IRK stays zero:
 * the sniffer has no identity. */
static int apply_keys(void)
{
	const uint8_t off = 0x00u;
	const uint8_t on = 0x01u;
	int err = send_command(BT_HCI_OP_LE_SET_ADDR_RES_ENABLE, &off, 1);

	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_LE_CLEAR_RL, NULL, 0);
	if (err != 0) {
		return err;
	}
	for (uint8_t i = 0; i < key_count; i++) {
		uint8_t entry[KEY_ENTRY + 16u] = {0};

		memcpy(entry, keys[i], KEY_ENTRY);
		err = send_command(BT_HCI_OP_LE_ADD_DEV_TO_RL, entry,
				   sizeof(entry));
		if (err != 0) {
			return err;
		}
		uint8_t mode[8];

		memcpy(mode, keys[i], 7u);      /* type and identity address */
		mode[7] = 0x01u;                /* device privacy mode */
		err = send_command(BT_HCI_OP_LE_SET_PRIVACY_MODE, mode,
				   sizeof(mode));
		if (err != 0) {
			return err;
		}
	}
	return key_count > 0u
	       ? send_command(BT_HCI_OP_LE_SET_ADDR_RES_ENABLE, &on, 1)
	       : 0;
}

/* Loads the accept list into the controller. Rebuilt on every scan start
 * because the reset above clears it. */
static int apply_filter(void)
{
	/* Keys first: the accept list may name identities that only the
	 * resolving list can recognise. */
	int err = apply_keys();

	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_LE_CLEAR_FAL, NULL, 0);
	if (err != 0) {
		return err;
	}
	for (uint8_t i = 0; i < filter_count; i++) {
		err = send_command(BT_HCI_OP_LE_ADD_DEV_TO_FAL,
				   filter[i], FILTER_ENTRY);
		if (err != 0) {
			return err;
		}
	}
	return 0;
}

int sn_radio_ble_stop(void)
{
	running = false;

	/* Keys are secrets; they live for one capture. */
	memset(keys, 0, sizeof(keys));
	key_count = 0u;

	/* Otherwise the last packets before a stop sit in the buffer until
	 * something else happens to arrive, which on a stopped radio is
	 * never. */
	(void)k_work_cancel_delayable(&ble_linger);
	k_mutex_lock(&block, K_FOREVER);
	ble_flush_locked();
	k_mutex_unlock(&block);

	const uint8_t disable[6] = {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};
	const int err = send_command(BT_HCI_OP_LE_SET_EXT_SCAN_ENABLE,
				     disable, sizeof(disable));

	/* And out of the controller. Its resolving list would otherwise keep
	 * the keys until the next capture's reset, and this board does not
	 * reset when its port opens. Resolution goes off first: the list
	 * cannot change while it is on. */
	const uint8_t off = 0x00u;

	(void)send_command(BT_HCI_OP_LE_SET_ADDR_RES_ENABLE, &off, 1);
	(void)send_command(BT_HCI_OP_LE_CLEAR_RL, NULL, 0);
	return err;
}

/* Zeroes the counters, when a host opens a session: this board does not
 * reboot when its port opens, so otherwise every capture would carry the
 * last one's counts. */
void sn_radio_ble_reset_counters(void)
{
	captured = 0u;
	adv_reports = 0u;
	forwarded = 0u;
	oversized = 0u;
	dropped = 0u;
	periodic_seen = 0u;
	periodic_synced = 0u;
	periodic_reports = 0u;
	periodic_refused = 0u;
}

void sn_radio_ble_get_stats(struct sn_ble_stats *out)
{
	*out = (struct sn_ble_stats){
		.hci_packets = captured,
		.adv_reports = adv_reports,
		.forwarded = forwarded,
		.oversized = oversized,
		.queue_full = 0u,
		.link_rejected = dropped,
		.command_timeouts = 0u,
		.periodic_seen = periodic_seen,
		.periodic_synced = periodic_synced,
		.periodic_reports = periodic_reports,
		.periodic_refused = periodic_refused,
	};
}
