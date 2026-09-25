#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Bluetooth LE advertisement capture on the nRF54L15.
 *
 * Advertisements only. This cannot follow a connection: doing that means
 * locking onto a connection request and hopping the data channels with it,
 * which needs link-layer access the controller does not expose over HCI. A
 * device that connects goes quiet here the moment it stops advertising.
 *
 * Passive scanning only: the controller never transmits a scan request, so
 * the sniffer stays silent. Scan responses therefore appear only when some
 * other device solicits them, which is the trade for not announcing yourself,
 * and is why the Name column in Wireshark is usually empty.
 *
 * The controller runs WITHOUT a host stack -- CONFIG_BT_HCI_RAW -- and is
 * driven straight over HCI, exactly as the ESP32-C6 firmware drives its own.
 * What reaches the host is the controller's own HCI events byte for byte, so
 * Wireshark dissects them with its HCI dissector rather than anything invented
 * here, and both boards produce the same bytes for the same air traffic.
 */

/* Metadata prepended to each forwarded HCI packet, 12 bytes, little-endian.
 * The HCI packet itself follows, starting with its H4 packet-type byte.
 *
 * Byte-identical to sn_ble_meta_t in the ESP32-C6 firmware, because the host
 * unpacks both with one "<QHBB" in esp32c6_sniffer/ble.py. A field that moves
 * here decodes into a confident wrong number there rather than an error. */
struct __attribute__((packed)) sn_ble_meta {
	uint64_t timestamp_us;  /* arrival at this firmware, microseconds up */
	uint16_t orig_len;      /* H4 packet length before any truncation */
	uint8_t flags;
	uint8_t reserved;
};

#define SN_BLE_FLAG_TRUNCATED 0x01u

/* Largest H4 packet forwarded, counting the type byte. An extended
 * advertising report can be long; anything past this is truncated and flagged
 * rather than dropped, because a truncated advertisement still carries its
 * address and RSSI. */
#define SN_BLE_MAX_PACKET 300

/* Scan defaults, matching the ESP32-C6 firmware. A window equal to the
 * interval is continuous scanning. */
#define SN_BLE_DEFAULT_INTERVAL_MS 60
#define SN_BLE_DEFAULT_WINDOW_MS   60

/* Brings up the controller and starts forwarding its events. Returns 0, or a
 * negative errno if the controller will not start. */
int sn_radio_ble_init(void);

/* Starts passive scanning. `phys` is a bitmask: 1 is the 1M PHY, 4 adds Coded
 * (long range); 0 is rejected rather than silently treated as 1M. Interval and
 * window are in milliseconds, as the host sends them. */
int sn_radio_ble_start(uint16_t interval_ms, uint16_t window_ms, uint8_t phys);

int sn_radio_ble_stop(void);

/* The controller's accept list: N entries of (address type, 6-byte address,
 * least significant byte first) exactly as the host frames them. An empty
 * payload clears it and scans everything again.
 *
 * Filtering in the CONTROLLER rather than here is the point: a rejected
 * advertisement is never reported and never crosses a 94 kB/s link. One
 * nearby device advertising at 21 a second was half of everything a survey
 * heard, so this is the difference between watching a device and watching a
 * room.
 *
 * Stored rather than applied: the list is loaded when a scan starts, because
 * the controller is reset at that point and forgets it. */
void sn_radio_ble_set_filter(const uint8_t *payload, size_t len);

/* Identity resolving keys: N x 23 bytes, (identity type, identity address,
 * key), the last two least significant first. Refused whole if malformed or
 * more than CONFIG_BT_CTLR_RL_SIZE. Loaded at the next scan start, before
 * the accept list; cleared when the scan stops. */
int sn_radio_ble_set_keys(const uint8_t *payload, size_t len);

/* Follows periodic advertising trains as they are noticed.
 *
 * An extended advertisement carries the interval of its periodic train, if it
 * has one. With this on, the firmware asks the controller to sync to each
 * train it sees, and the periodic reports then arrive as ordinary HCI events
 * and are forwarded like everything else -- which is how LE Audio and
 * Auracast broadcasts become visible at all.
 *
 * Off by default. Syncing costs receive windows the scanner would otherwise
 * spend on advertisements, so a capture that does not want periodic traffic
 * should not pay for it. */
void sn_radio_ble_set_periodic(bool enable);

/* Counters for the STATS frame.
 *
 * Field for field, in order, the same as sn_ble_stats_t in the ESP32-C6
 * firmware, because the host reads one block by position for both boards and
 * decides from the payload's length how many counters arrived. A field that
 * moves here decodes as the one after it there.
 *
 * Three are always zero on this board, and deliberately: there is no
 * intermediate receive queue to overflow, and send_command does not wait for
 * a controller answer, so neither a queue-full nor a command timeout is a
 * measurement this firmware can make. Reporting anything but zero for them
 * would invent one. */
struct sn_ble_stats {
	uint32_t hci_packets;      /* events and ISO packets handed over */
	uint32_t adv_reports;      /* of those, LE advertising reports */
	uint32_t forwarded;        /* packets the link accepted */
	uint32_t oversized;        /* truncated to SN_BLE_MAX_PACKET */
	uint32_t queue_full;       /* always 0: no such queue here */
	uint32_t link_rejected;    /* packets the outbound ring refused */
	uint32_t command_timeouts; /* always 0: commands are not awaited */
	uint32_t periodic_seen;    /* advertisers announcing a periodic train */
	uint32_t periodic_synced;  /* syncs the controller established */
	uint32_t periodic_reports; /* periodic advertising reports received */
	uint32_t periodic_refused; /* syncs the controller would not establish */
};

void sn_radio_ble_get_stats(struct sn_ble_stats *out);
void sn_radio_ble_reset_counters(void);
