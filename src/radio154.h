#pragma once

#include <stdint.h>

/* Mirrors sn_154_meta_t in firmware/main/radio154.h, which the host unpacks as
 * "<BBbBQ" in capture.py. Packed because the host reads it as a flat
 * little-endian struct with no padding, and a field that moves here decodes
 * into a confident wrong number there rather than an error. */
struct __attribute__((packed)) sn_154_meta {
	uint8_t  channel;
	uint8_t  lqi;
	int8_t   rssi_dbm;
	uint8_t  flags;
	uint64_t timestamp_us;
};

/* Binds the radio and configures it for sniffing. Must be called before
 * sn_radio154_start(). Returns 0 on success. */
int sn_radio154_init(void);

int sn_radio154_set_channel(uint8_t channel);
int sn_radio154_start(void);
int sn_radio154_stop(void);

uint8_t sn_radio154_channel(void);

/* Measures the energy on one channel and reports the peak in dBm, then puts
 * the radio back exactly as it was: receiving on its own channel if a capture
 * was running, asleep if not.
 *
 * `duration_symbols` is in 16 us symbols, as the wire format and the ESP32-C6
 * carry it. The driver measures in whole milliseconds, so the window is
 * rounded UP -- a peak found over a longer window can only be higher, which
 * errs toward calling a channel busy rather than quiet.
 *
 * Blocks for the window plus a margin. The caller is the link reader thread,
 * which is waiting for exactly this reply. Returns 0, -EINVAL for a channel or
 * window that cannot be measured, or another negative errno if the driver
 * would not measure. */
int sn_radio154_energy_detect(uint8_t channel, uint32_t duration_symbols,
			      int8_t *out_dbm);

/* Counters for the STATS frame. */
uint32_t sn_radio154_captured(void);
uint32_t sn_radio154_dropped(void);
/* Frames the radio discarded for a bad FCS: counted, never captured. */
uint32_t sn_radio154_fcs_failed(void);
