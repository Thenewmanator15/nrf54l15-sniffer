/* The XIAO nRF54L15 half of the sniffer.
 *
 * Speaks the same wire format as the ESP32-C6 firmware, by compiling the same
 * frame.c rather than reimplementing it. See shared/frame.h.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "control.h"
#include "frame.h"
#include "link.h"
#include "radio154.h"
#include "radio_ble.h"

/* Wire format this firmware speaks. Must match the nrf54l15 entry in
 * EXPECTED_FIRMWARE_VERSIONS in host/src/esp32c6_sniffer/capture.py; the host
 * refuses to open a capture until the two agree, because an older board packs
 * its metadata differently and every field would then decode to a confident
 * wrong number rather than an error. */
#define SN_FIRMWARE_VERSION 3u

LOG_MODULE_REGISTER(sniffer, LOG_LEVEL_INF);

#ifndef SN_MODE
#define SN_MODE 0
#endif

#define SN_MODE_CONFORMANCE 0
#define SN_MODE_CAPTURE     2

uint32_t sn_firmware_version(void)
{
	return SN_FIRMWARE_VERSION;
}

#if SN_MODE == SN_MODE_CONFORMANCE
/* The same burst firmware/main/main.c emits, in the same order, so the host's
 * existing conformance test holds BOTH boards to one set of vectors without
 * knowing there is more than one board. Payloads are transcribed from
 * host/tests/vectors/golden.json; the sequence numbers are assigned by the
 * link at runtime, which is why the host compares types and payloads and then
 * re-encodes to check the bytes. */
static void conformance_burst(void)
{
	static uint8_t all_bytes[256];

	for (int i = 0; i < 256; i++) {
		all_bytes[i] = (uint8_t)i;
	}
	static const uint8_t newline_bytes[] = {0x0a, 0x0d, 0x0a, 0x00, 0xff};
	static const char hello[] = "hello";
	static const char wrap[] = "wrap";
	static const char logmsg[] = "I (123) tag: msg";
	/* A three-entry batch on channel 25 -- base 1000000 us, deltas 0/450/2550,
	 * the last entry a real acknowledgement -- and a ring 48000 bytes deep
	 * with a 128 KB high-water mark of 192 KB capacity. Transcribed from
	 * host/tests/vectors/golden.json; the layouts are authoritative in
	 * host/src/esp32c6_sniffer/batch.py. */
	static const uint8_t batch_three[] = {
		0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x03,
		0x00, 0x00, 0xc8, 0xc4, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
		0xc2, 0x01, 0xc7, 0xc3, 0x05, 0x0a, 0x0d, 0x0a, 0x00, 0xff,
		0xf6, 0x09, 0x00, 0x9e, 0x05, 0x02, 0x00, 0x1e, 0x00, 0xf2,
	};
	static const uint8_t link_status[] = {
		0x80, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00,
	};

	while (true) {
		sn_link_send(SN_FRAME_HEARTBEAT, NULL, 0);
		sn_link_send(SN_FRAME_PACKET, (const uint8_t *)hello, sizeof(hello) - 1);
		sn_link_send(SN_FRAME_PACKET, newline_bytes, sizeof(newline_bytes));
		sn_link_send(SN_FRAME_PACKET, all_bytes, sizeof(all_bytes));
		sn_link_send(SN_FRAME_PACKET, (const uint8_t *)wrap, sizeof(wrap) - 1);
		sn_link_send(SN_FRAME_LOG, (const uint8_t *)logmsg, sizeof(logmsg) - 1);
		/* PACKET_BATCH and LINK, identical bytes to firmware/main/main.c and
		 * to golden.json, in the same position in the burst. */
		sn_link_send(SN_FRAME_PACKET_BATCH, batch_three, sizeof(batch_three));
		sn_link_send(SN_FRAME_LINK, link_status, sizeof(link_status));
		k_sleep(K_MSEC(500));
	}
}
#endif

#if SN_MODE == SN_MODE_CAPTURE
/* Published once a second, laid out exactly as the ESP-IDF firmware lays it
 * out: five link counters, three for the 802.15.4 radio, thirteen for Wi-Fi
 * and eleven for BLE. The host reads all four blocks by position and decides
 * from the payload's length how many counters a given firmware sent.
 *
 * The Wi-Fi block is thirteen zeros and stays: this board has no Wi-Fi radio,
 * but the BLE block sits behind that space and every counter in it would be
 * read as a Wi-Fi one if it were closed up.
 *
 * Thirteen because the C6's sn_80211_stats_t is thirteen wide -- it ends with
 * fcs_length_unknown. This said twelve, copied from what the host once read
 * rather than from what the C6 sends, and when the host was corrected to
 * thirteen every BLE counter here moved one place: a board reporting more
 * advertising reports than HCI packets, which a subset cannot be.
 * test_stats_layout.py now checks this width against the C6's header.
 *
 * Sending BLE is new. The counters existed and reached nobody -- two
 * accessors that nothing called -- so a BLE capture here reported
 * sn_radio154_captured(), which is a stopped radio's zero, and the file's
 * statistics block said no loss whatever the link had refused.
 *
 * frames_dropped_ringfull is a real measurement: the outbound ring can fill
 * if the host stops draining, and a frame refused at that point is loss the
 * operator should be told about. short_writes and tx_stalls stay zero
 * deliberately -- this link does not detect either, so reporting anything but
 * zero would invent a measurement.
 *
 * Not packed, and the C6's copy is not either: every member is a uint32_t, so
 * the layout is already gap-free at four-byte alignment, and packing it would
 * only make taking the address of the BLE block unsafe. */
struct sn_stats_full {
	uint32_t frames_sent;
	uint32_t frames_dropped_ringfull;
	uint32_t short_writes;
	uint32_t tx_stalls;
	uint32_t bytes_sent;
	uint32_t frames_captured;
	uint32_t isr_queue_full;
	uint32_t link_rejected;
	uint32_t wifi[13];
	struct sn_ble_stats ble;
};

/* The outbound ring's occupancy, unpacked by the host as "<III". Occupancy
 * only -- frames refused because the ring was full travel in STATS above, and
 * counting them here as well would double them in the pcapng statistics.
 *
 * queued_bytes is how far behind real time the host is; divide by the drain
 * rate for seconds. high_water is the worst it reached this session, which is
 * the number that survives a burst nobody was watching for. */
struct __attribute__((packed)) sn_link_status {
	uint32_t queued_bytes;
	uint32_t high_water;
	uint32_t capacity;
};

static void stats_tick(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(stats_work, stats_tick);

static void stats_tick(struct k_work *work)
{
	ARG_UNUSED(work);

	struct sn_stats_full stats = {
		.frames_sent = sn_link_frames_sent(),
		.frames_dropped_ringfull = sn_link_frames_dropped(),
		.short_writes = 0u,
		.tx_stalls = 0u,
		.bytes_sent = sn_link_bytes_sent(),
		.frames_captured = sn_radio154_captured(),
		.isr_queue_full = 0u,
		.link_rejected = sn_radio154_dropped(),
		.wifi = {0},
	};

	/* Both radios' counters go in every frame, whichever is running, for
	 * the reason the C6 firmware gives: sending only the active one
	 * leaves the host unable to tell a zero counter from an absent one. */
	sn_radio_ble_get_stats(&stats.ble);

	sn_link_send(SN_FRAME_STATS, (const uint8_t *)&stats, sizeof(stats));

	/* Sent after STATS and measured before itself: the figure describes
	 * what was waiting, not what this frame added. */
	const struct sn_link_status link = {
		.queued_bytes = sn_link_queued(),
		.high_water = sn_link_high_water(),
		.capacity = sn_link_capacity(),
	};

	sn_link_send(SN_FRAME_LINK, (const uint8_t *)&link, sizeof(link));
	k_work_schedule(&stats_work, K_SECONDS(1));
}
#endif

int main(void)
{
	if (sn_link_init() != 0) {
		return -1;
	}

#if SN_MODE == SN_MODE_CONFORMANCE
	conformance_burst();
#elif SN_MODE == SN_MODE_CAPTURE
	if (sn_radio154_init() != 0) {
		return -1;
	}
	/* The controller is brought up but not scanning. Both radios are
	 * initialised at boot and neither is receiving: which one runs is the
	 * host's choice, made with SET_RADIO, and they share one antenna so
	 * only one can run at a time regardless.
	 *
	 * A failure here is not fatal to 802.15.4 capture, which is the
	 * radio this board was built for, so it is reported and stepped over
	 * rather than taking the firmware down with it. */
	if (sn_radio_ble_init() != 0) {
		LOG_ERR("Bluetooth controller would not start; 802.15.4 only");
	}
	sn_link_set_frame_handler(sn_control_handle);

	/* Travels as a LOG frame, not as bytes on the UART. If this ever
	 * appears as raw text in a capture, the backend is not installed and
	 * the data path is being corrupted. */
	LOG_INF("link up, mode=%d, firmware=%u", SN_MODE, SN_FIRMWARE_VERSION);

	/* The radio is NOT started here. For 802.15.4 the host sends no
	 * separate START -- SET_CHANNEL starts it, as capture.py's _configure
	 * says -- and starting at boot would capture on the default channel
	 * throughout the handshake and then attribute those frames to
	 * whichever channel was finally asked for. */
	k_work_schedule(&stats_work, K_SECONDS(1));

	while (true) {
		k_sleep(K_FOREVER);
	}
#endif
	return 0;
}
