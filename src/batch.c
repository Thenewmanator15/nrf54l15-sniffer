#include "batch.h"

#include <string.h>

#include <zephyr/kernel.h>

#include "frame.h"
#include "link.h"
#include "radio154.h"

/* Limits from the wire format. The host rejects a batch that breaks any of
 * them rather than decoding half of one, so an encoder that produced one would
 * be producing frames no host will read. */
#define MAX_ENTRIES 32
#define MAX_PSDU    127
#define MAX_DT_US   0xFFFFu

#define HEADER_LEN  10   /* u64 base timestamp, u8 channel, u8 count */
#define ENTRY_LEN   5    /* u16 dt, u8 lqi, i8 rssi, u8 len */

/* Static, and deliberately so: this is filled from the radio driver's RX
 * thread, whose stack overflowing is the fault that cost days and that
 * docs/2026-09-14-nrf54l15-spike.md exists to document. 4234 bytes against
 * 256 KB of RAM is a trade worth making without thinking about it twice. */
static uint8_t buf[HEADER_LEN + MAX_ENTRIES * (ENTRY_LEN + MAX_PSDU)];
static size_t used = HEADER_LEN;   /* header written at flush, not at open */
static uint8_t count;
static uint64_t base_us;
static uint64_t last_us;
static uint8_t batch_channel;
static uint32_t dropped_packets;

/* Two contexts touch the buffer: the RX thread adding, and the system work
 * queue flushing on the linger timer. */
static K_MUTEX_DEFINE(lock);
static void linger_expired(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(linger, linger_expired);

static void put_le16(uint8_t *at, uint16_t v)
{
	at[0] = (uint8_t)(v & 0xFFu);
	at[1] = (uint8_t)(v >> 8);
}

/* Sends the open batch. The caller holds the lock. */
static void flush_locked(void)
{
	if (count == 0u) {
		return;
	}

	/* A batch of one is sent as a PACKET instead, because as a batch it
	 * would be BIGGER than the frame it replaces: 10 bytes of frame
	 * header, 10 of batch header and a 5-byte entry is 25, against 22 for
	 * a PACKET's header and metadata. Batching wins by amortising that
	 * batch header across many packets, so with one packet it loses.
	 *
	 * This is not a rare corner. A sniffer spends most of its life on a
	 * quiet channel, where the linger timer expires before a second
	 * packet ever arrives -- measured at 38 of 44 batches on this bench.
	 * Without this branch, batching would have made the common case three
	 * bytes per packet worse in exchange for the busy case being better. */
	if (count == 1u) {
		const uint8_t *entry = buf + HEADER_LEN;
		const uint8_t len = entry[4];
		/* Static for the same reason the batch buffer is: this can run
		 * on the radio driver's RX thread. The mutex the caller holds
		 * is what makes one shared scratch buffer safe. */
		static uint8_t one[sizeof(struct sn_154_meta) + MAX_PSDU];
		const struct sn_154_meta meta = {
			.channel = batch_channel,
			.lqi = entry[2],
			.rssi_dbm = (int8_t)entry[3],
			/* Always clear: the driver strips the FCS before we
			 * see a frame, which is why batch entries have no
			 * flags field to carry it in. */
			.flags = 0u,
			/* The first entry's delta is measured from the base,
			 * so it is zero and this is its exact capture time. */
			.timestamp_us = base_us,
		};

		memcpy(one, &meta, sizeof(meta));
		memcpy(one + sizeof(meta), entry + ENTRY_LEN, len);

		if (sn_link_send(SN_FRAME_PACKET, one,
				 sizeof(meta) + len) != 0) {
			dropped_packets++;
		}

		count = 0u;
		used = HEADER_LEN;
		return;
	}

	/* The header is written now rather than when the batch opened,
	 * because count is not known until it closes. */
	for (int i = 0; i < 8; i++) {
		buf[i] = (uint8_t)(base_us >> (8 * i));
	}
	buf[8] = batch_channel;
	buf[9] = count;

	/* A refused batch is every packet in it, not one drop. Counting it
	 * as one would report a thirty-second of the loss, and a sniffer that
	 * understates what it lost is worse than one that says nothing. */
	if (sn_link_send(SN_FRAME_PACKET_BATCH, buf, used) != 0) {
		dropped_packets += count;
	}

	count = 0u;
	used = HEADER_LEN;
}

static void linger_expired(struct k_work *work)
{
	ARG_UNUSED(work);

	k_mutex_lock(&lock, K_FOREVER);
	flush_locked();
	k_mutex_unlock(&lock);
}

void sn_batch_flush(void)
{
	/* Cancel first: a flush that has already been asked for would
	 * otherwise fire against an empty buffer and do nothing, which is
	 * harmless but makes the work queue look busier than it is. */
	(void)k_work_cancel_delayable(&linger);

	k_mutex_lock(&lock, K_FOREVER);
	flush_locked();
	k_mutex_unlock(&lock);
}

uint32_t sn_batch_dropped(void)
{
	return dropped_packets;
}

void sn_batch_add(uint8_t channel, uint64_t timestamp_us, uint8_t lqi,
		  int8_t rssi_dbm, const uint8_t *psdu, size_t len)
{
	if (len > MAX_PSDU) {
		len = MAX_PSDU;
	}

	k_mutex_lock(&lock, K_FOREVER);

	/* Three things close a batch early, and all three are conditions the
	 * host would reject the frame for rather than tolerate.
	 *
	 * A timestamp going backwards is the odd one. It should not happen --
	 * the clock is monotonic -- but if it ever did, a negative delta would
	 * wrap the unsigned subtraction into an enormous one and hand the host
	 * a confidently wrong time. Closing the batch keeps the damage to one
	 * frame's ordering instead. */
	if (count > 0u &&
	    (channel != batch_channel ||
	     timestamp_us < last_us ||
	     timestamp_us - last_us > MAX_DT_US)) {
		flush_locked();
	}

	if (count == 0u) {
		base_us = timestamp_us;
		batch_channel = channel;
		last_us = timestamp_us;
	}

	/* First entry's delta is measured from the base, so it is zero. */
	const uint16_t dt = (uint16_t)(timestamp_us - last_us);

	uint8_t *at = buf + used;
	put_le16(at, dt);
	at[2] = lqi;
	at[3] = (uint8_t)rssi_dbm;
	at[4] = (uint8_t)len;
	memcpy(at + ENTRY_LEN, psdu, len);

	used += ENTRY_LEN + len;
	last_us = timestamp_us;
	count++;

	if (count == MAX_ENTRIES) {
		flush_locked();
		(void)k_work_cancel_delayable(&linger);
	} else {
		/* Rescheduled on every packet, so the timer measures silence
		 * rather than the age of the batch. A busy channel therefore
		 * fills batches and a quiet one still delivers promptly. */
		(void)k_work_reschedule(&linger, K_MSEC(SN_BATCH_LINGER_MS));
	}

	k_mutex_unlock(&lock);
}
