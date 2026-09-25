#pragma once

#include <stddef.h>
#include <stdint.h>

#include "frame.h"

/* Brings up the UART the host reads, and starts the reader that feeds
 * sn_link_set_command_handler. Returns 0, or -ENODEV if the device is not
 * ready. */
int sn_link_init(void);

/* Frames a payload and writes it. Assigns the sequence number itself, so
 * nothing above this layer has to track one -- which is also why the host
 * matches command replies by echoed command id rather than by sequence.
 * Returns 0 on success. */
int sn_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len);

/* Called for each frame the host sends, with its type, so one handler can
 * route them. The type is passed rather than assumed because the host sends
 * more than commands: BLE_FILTER carries an accept list, and a second setter
 * per frame type would multiply with every one added.
 *
 * Runs on the link's reader thread, never in an ISR, so it may block
 * briefly. */
typedef void (*sn_frame_handler_t)(uint8_t type, const uint8_t *payload,
				   size_t len);
void sn_link_set_frame_handler(sn_frame_handler_t handler);

/* Counters for the STATS frame. Kept here because this is the only place that
 * knows what actually reached the wire. */
void sn_link_reset_counters(void);
uint32_t sn_link_frames_sent(void);
uint32_t sn_link_bytes_sent(void);

/* Frames refused because the outbound ring was full. Real loss, reported to
 * the host rather than hidden: a sniffer that quietly discards is worse than
 * one that says how much it discarded. */
uint32_t sn_link_frames_dropped(void);

/* The outbound ring's occupancy, for the LINK frame. Occupancy ONLY: frames
 * refused because it was full are counted above and already reach the host in
 * STATS, and carrying them here too would double them in the pcapng
 * interface-statistics blocks.
 *
 * Worth having because drops answer "did I lose anything?" only after the
 * fact, while queue depth answers "am I about to?" -- a ring climbing towards
 * capacity is the warning that precedes the first drop. */
uint32_t sn_link_queued(void);
uint32_t sn_link_high_water(void);
uint32_t sn_link_capacity(void);
