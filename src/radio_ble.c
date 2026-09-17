#include "radio_ble.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net_buf.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/buf.h>
#include <zephyr/bluetooth/hci_raw.h>
#include <zephyr/bluetooth/hci_types.h>

#include "frame.h"
#include "link.h"

/* H4 packet type for an HCI event. In raw mode the type is a property of the
 * net_buf rather than a byte inside it, so it is put back on the front here --
 * the host's dissector expects H4 framing, starting with this byte. */
#define H4_EVENT 0x04u

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
#define FILTER_ACCEPT_ALL 0x00u
#define SCAN_TYPE_PASSIVE 0x00u   /* never transmit; the whole point */

/* HCI uses 0.625 ms units for scan interval and window. */
#define UNITS_PER_MS(ms) ((uint16_t)(((uint32_t)(ms) * 1000u) / 625u))

static K_FIFO_DEFINE(hci_rx);
static bool running;
static uint32_t captured;
static uint32_t dropped;

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

static uint64_t now_us(void)
{
	/* Arrival at this firmware, not at the antenna: the controller does
	 * not expose a radio timestamp over HCI. Honest about being that,
	 * exactly as the C6's esp_timer reading is. */
	return k_ticks_to_us_floor64(k_uptime_ticks());
}

/* Sends one HCI command and waits for the controller to take it. */
static int send_command(uint16_t opcode, const uint8_t *params, uint8_t len)
{
	struct net_buf *buf = bt_buf_get_tx(BT_BUF_CMD, K_SECONDS(1), NULL, 0);

	if (buf == NULL) {
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

	const int err = bt_send(buf);

	/* Raw mode has no host stack, so nothing is tracking the controller's
	 * command credit for us. Setup is five commands back to back and this
	 * is the cheap way to stay inside one outstanding command; it costs
	 * 100 ms once, at the start of a capture. */
	k_msleep(20);
	return err;
}

static void forward(struct net_buf *buf)
{
	/* One more byte than the event, for the H4 type put back on the
	 * front. The host counts orig_len the same way. */
	const uint16_t full = (uint16_t)(buf->len + 1u);
	uint16_t take = full;
	uint8_t flags = 0u;

	if (take > SN_BLE_MAX_PACKET) {
		take = SN_BLE_MAX_PACKET;
		flags |= SN_BLE_FLAG_TRUNCATED;
	}

	const struct sn_ble_meta meta = {
		.timestamp_us = now_us(),
		.orig_len = full,
		.flags = flags,
		.reserved = 0u,
	};

	memcpy(out, &meta, sizeof(meta));
	out[sizeof(meta)] = H4_EVENT;
	memcpy(out + sizeof(meta) + 1, buf->data, take - 1u);

	captured++;
	if (sn_link_send(SN_FRAME_PACKET, out,
			 sizeof(meta) + take) != 0) {
		dropped++;
	}
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

		/* Only events, and only once scanning has been enabled. The
		 * controller answers every setup command with a command
		 * complete, and a capture should contain what the radio heard
		 * rather than our own configuration. */
		if (running && bt_buf_get_type(buf) == BT_BUF_EVT) {
			forward(buf);
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

	const uint16_t interval = UNITS_PER_MS(interval_ms);
	const uint16_t window = UNITS_PER_MS(window_ms);

	uint8_t params[3 + 8 * 5];
	uint8_t n = 0;

	params[n++] = OWN_ADDR_RANDOM;
	params[n++] = FILTER_ACCEPT_ALL;
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

	/* Set last: everything above is configuration, and forwarding it
	 * would put our own command completes in the capture. */
	running = true;
	return 0;
}

int sn_radio_ble_stop(void)
{
	running = false;

	const uint8_t disable[6] = {0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u};

	return send_command(BT_HCI_OP_LE_SET_EXT_SCAN_ENABLE,
			    disable, sizeof(disable));
}

uint32_t sn_radio_ble_captured(void)
{
	return captured;
}

uint32_t sn_radio_ble_dropped(void)
{
	return dropped;
}
