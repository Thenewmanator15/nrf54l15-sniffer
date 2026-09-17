#pragma once

#include <stdint.h>
#include <stddef.h>

/* Accumulates captured packets into SN_FRAME_PACKET_BATCH frames.
 *
 * A PACKET frame costs 10 bytes of header plus 12 of metadata, so a 5-byte
 * acknowledgement travels as 27 bytes. This board's link to the host is a UART
 * through the SAMD11 bridge, measured at 94.3 kB/s, and that overhead is most
 * of the budget on a channel carrying small frames back to back. One header
 * shared across up to 32 packets, the channel stated once and timestamps
 * delta-coded, brings it to about 5.6 bytes per packet.
 *
 * Every packet keeps its own capture timestamp, reconstructed exactly by the
 * host, so nothing about timing accuracy changes. What does change is when
 * frames reach the host: up to SN_BATCH_LINGER_MS later than they would have.
 * Wireshark shows capture time, not arrival time, so this is invisible in a
 * capture and visible only as latency on screen.
 *
 * A batch that closes with a single packet in it is sent as an ordinary
 * PACKET frame, because as a batch it would be three bytes larger than the
 * frame it replaces. That is the usual case on a quiet channel, so without it
 * batching would cost more than it saved most of the time.
 *
 * The layout is authoritative in the host package's esp32c6_sniffer/batch.py.
 */

/* Adds one captured packet, flushing first if it cannot join the open batch.
 *
 * Cannot fail at this point: the packet is copied into the open batch, and
 * whether it reaches the host is decided later, when that batch is sent. See
 * sn_batch_dropped().
 *
 * Called from the radio driver's RX thread. That thread's stack is the one
 * documented in the spike log as fatally tight, so everything here is static
 * and nothing large lands on it.
 */
void sn_batch_add(uint8_t channel, uint64_t timestamp_us, uint8_t lqi,
		  int8_t rssi_dbm, const uint8_t *psdu, size_t len);

/* Packets lost because the outbound ring was full when their batch was sent.
 *
 * Counted in PACKETS rather than frames, which is the number an operator
 * actually wants: one refused batch is up to 32 packets gone, and reporting
 * it as a single drop would understate the loss thirty-twofold. */
uint32_t sn_batch_dropped(void);

/* Sends whatever is buffered, if anything. Safe to call when empty.
 *
 * Called on the linger timer, and directly when capture stops or the channel
 * is retuned -- otherwise the last packets before a stop would sit in the
 * buffer until something else happened to arrive. */
void sn_batch_flush(void);

/* How long an incomplete batch waits for company before it is sent anyway.
 *
 * Bounds the latency a batch can add. It is also what keeps the 16-bit delta
 * field from ever overflowing in practice: a gap wider than 65535 us closes a
 * batch, and this timer closes one long before such a gap can open. The
 * overflow is still checked, because correctness should not rest on a timer
 * having been scheduled promptly. */
#define SN_BATCH_LINGER_MS 20
