/* Control channel, host to board.
 *
 * The host's side is esp32c6_sniffer.control. Commands arrive framed exactly
 * as everything else does, so the same parser handles both directions.
 *
 * Payload layouts, from that module's docstring:
 *   command  5 bytes  "<BI"   command id, then a little-endian 32-bit value
 *   reply    6 bytes  "<BBI"  echoed command id, status, then a value
 *
 * The command id is echoed rather than correlated by sequence number, because
 * the board assigns sequence numbers and the host cannot know them in advance.
 *
 * Only the commands this board can honour are implemented. Every other id gets
 * SN_STATUS_UNKNOWN_COMMAND rather than silence: the host tolerates a reply it
 * does not recognise, but a missing one stalls it until a timeout.
 */

#include "control.h"

#include <zephyr/logging/log.h>

#include <stddef.h>
#include <stdint.h>

#include "commands.h"
#include "frame.h"
#include "link.h"
#include "radio154.h"
#include "radio_ble.h"

LOG_MODULE_REGISTER(control, LOG_LEVEL_INF);

#define SN_CMD_PAYLOAD_LEN   5
#define SN_REPLY_PAYLOAD_LEN 6

/* From esp32c6_sniffer.control.Radio. BLE is 2, not 1 -- 1 is Wi-Fi, which
 * this part does not have. Guessing 1 here made the board accept a request
 * for Wi-Fi as though it were BLE and refuse the real thing, and the host
 * reported only "SET_RADIO failed, status 2". */
#define RADIO_154 0u
#define RADIO_WIFI 1u
#define RADIO_BLE 2u

/* Which radio the host selected. SET_CHANNEL, START and STOP are all
 * interpreted against it, so it is tracked rather than inferred: a START that
 * guessed wrong would start the other radio and capture nothing the operator
 * asked for. */
static uint8_t selected_radio = RADIO_154;

/* Held until START, because the host sends them before it. Zero means "not
 * set", which the radio turns into its default. */
static uint16_t ble_interval_ms;
static uint16_t ble_window_ms;
static uint8_t ble_phys = 1u;   /* the 1M PHY, which every advertiser uses */

static void reply(uint8_t command, uint8_t status, uint32_t value)
{
	uint8_t out[SN_REPLY_PAYLOAD_LEN];

	out[0] = command;
	out[1] = status;
	out[2] = (uint8_t)(value & 0xFFu);
	out[3] = (uint8_t)((value >> 8) & 0xFFu);
	out[4] = (uint8_t)((value >> 16) & 0xFFu);
	out[5] = (uint8_t)((value >> 24) & 0xFFu);

	sn_link_send(SN_FRAME_CONTROL_REPLY, out, sizeof(out));
}

void sn_control_handle(const uint8_t *payload, size_t len)
{
	if (len < SN_CMD_PAYLOAD_LEN) {
		return;
	}
	const uint8_t command = payload[0];
	const uint32_t value = (uint32_t)payload[1] |
			       ((uint32_t)payload[2] << 8) |
			       ((uint32_t)payload[3] << 16) |
			       ((uint32_t)payload[4] << 24);

	switch (command) {
	case SN_CMD_SET_RADIO:
		/* The host selects a radio before anything else, because
		 * SET_CHANNEL, START and STOP are interpreted against
		 * whichever is selected.
		 *
		 * Two exist here. Wi-Fi is RADIO_WIFI and does not exist on
		 * this part at all, so it is refused rather than quietly
		 * accepted. */
		if (value != RADIO_154 && value != RADIO_BLE) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		selected_radio = (uint8_t)value;
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_SET_BLE_PHYS:
		/* 1 is the 1M PHY, 4 adds Coded. Zero would ask the controller
		 * to scan on no PHY, which it accepts and which hears nothing,
		 * so it is refused here rather than at the radio. */
		if (value == 0u || value > 0xFFu) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		ble_phys = (uint8_t)value;
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_SET_BLE_SCAN:
		/* Interval in the low 16 bits, window in the high 16, as
		 * capture.py packs them. Stored rather than applied: the host
		 * sends this before START, and the controller takes both in
		 * one command when scanning is configured. */
		ble_interval_ms = (uint16_t)(value & 0xFFFFu);
		ble_window_ms = (uint16_t)(value >> 16);
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_SET_CHANNEL:
		/* BLE has no channel: the controller rotates the three
		 * advertising channels itself, and the host knows this and
		 * sends START instead. Arriving here means the host and the
		 * board disagree about the selected radio, which is worth a
		 * refusal rather than retuning a radio nobody asked about. */
		if (selected_radio == RADIO_BLE) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		/* SET_CHANNEL starts the radio, which is what the host
		 * expects: for 802.15.4 it sends no separate START, and the
		 * comment in capture.py's _configure says so explicitly.
		 * Starting here rather than at boot also means nothing is
		 * captured on the default channel during the handshake and
		 * then attributed to the channel that was asked for. */
		if (sn_radio154_set_channel((uint8_t)value) != 0) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		/* Worth saying out loud. The operator picked a channel and the
		 * capture is about to be attributed to it, so a mismatch
		 * between what was asked for and what the radio took is the
		 * kind of thing that should be visible rather than inferred. */
		if (sn_radio154_start() != 0) {
			LOG_ERR("channel %u set but the radio would not start",
				(unsigned)value);
			reply(command, SN_STATUS_FAILED, value);
			break;
		}
		LOG_INF("channel %u, receiving", (unsigned)value);
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_START:
		if (selected_radio == RADIO_BLE) {
			const int err = sn_radio_ble_start(ble_interval_ms,
							   ble_window_ms,
							   ble_phys);

			if (err != 0) {
				LOG_ERR("BLE scan would not start: %d", err);
			}
			reply(command,
			      err == 0 ? SN_STATUS_OK : SN_STATUS_FAILED, 0u);
			break;
		}
		reply(command,
		      sn_radio154_start() == 0 ? SN_STATUS_OK : SN_STATUS_FAILED,
		      0u);
		break;

	case SN_CMD_STOP:
		if (selected_radio == RADIO_BLE) {
			reply(command,
			      sn_radio_ble_stop() == 0 ? SN_STATUS_OK
						       : SN_STATUS_FAILED,
			      0u);
			break;
		}
		reply(command,
		      sn_radio154_stop() == 0 ? SN_STATUS_OK : SN_STATUS_FAILED,
		      0u);
		break;

	case SN_CMD_GET_INFO:
		/* The host refuses to open a capture until this matches
		 * EXPECTED_FIRMWARE_VERSIONS["nrf54l15"], because an older
		 * board packs its metadata differently and every field would
		 * then decode to a confident wrong number rather than an
		 * error. */
		reply(command, SN_STATUS_OK, sn_firmware_version());
		break;

	case SN_CMD_SET_ANTENNA:
		/* This board does have an RF switch, but which position
		 * selects which antenna is not established -- see
		 * docs/2026-09-14-nrf54l15-spike.md.
		 *
		 * Antenna.INTERNAL == 0 is "leave it as the board brought it
		 * up", which is exactly what happens here, so it is honest to
		 * accept it. Asking for the external antenna is refused rather
		 * than accepted and ignored: a control that silently does
		 * nothing is worse than one that says it cannot. */
		reply(command,
		      value == 0u ? SN_STATUS_OK : SN_STATUS_BAD_VALUE,
		      value);
		break;

	default:
		reply(command, SN_STATUS_UNKNOWN_COMMAND, 0u);
		break;
	}
}
