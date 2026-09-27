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

#include <zephyr/drivers/regulator.h>
#include <zephyr/logging/log.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "batch.h"
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

/* The board's antenna switch: a regulator-fixed node on gpio2.5, active low
 * and on at boot. On (low) is the onboard ceramic antenna, off (high) the
 * IPEX connector: Seeed's getting-started guide for this board sets the pin
 * low for ceramic, its default, and high for external. Measured on a board
 * with an antenna fitted, switching reads every advertiser about 14.5 dB
 * apart, so the switch does switch. */
static const struct device *const rfsw_ctl = DEVICE_DT_GET(DT_NODELABEL(rfsw_ctl));

/* Antenna.INTERNAL is 0 and Antenna.EXTERNAL 1, as the host numbers them.
 * Through the regulator API rather than the pin, because the regulator
 * driver owns the pin; is_enabled keeps its reference count at one. */
static int set_antenna(uint32_t value)
{
	if (value > 1u) {
		return -EINVAL;
	}
	if (!device_is_ready(rfsw_ctl)) {
		return -ENODEV;
	}
	const bool onboard = value == 0u;

	if (onboard == regulator_is_enabled(rfsw_ctl)) {
		return 0;
	}
	return onboard ? regulator_enable(rfsw_ctl) : regulator_disable(rfsw_ctl);
}

/* Stops a radio, 802.15.4 with its open batch sent first, so the host sees
 * every packet before the reply that says capture has stopped. BLE resets
 * the controller whether it was scanning or not -- a START that failed
 * part-way has already loaded keys and a filter -- provided it came up at
 * all. */
static int stop_radio(uint8_t radio)
{
	if (radio == RADIO_BLE) {
		/* Not when the controller never came up: nothing would answer
		 * the reset, and GET_INFO would wait on it every session. */
		return sn_radio_ble_ready() ? sn_radio_ble_stop() : 0;
	}
	const int err = sn_radio154_stop();

	sn_batch_flush();
	return err;
}

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

void sn_control_handle(uint8_t type, const uint8_t *payload, size_t len)
{
	/* BLE_FILTER is a frame rather than a command: an accept list does not
	 * fit in a command's single 32-bit value. It is answered with no reply
	 * because the host sends it and moves on, exactly as it does to the
	 * ESP32-C6. */
	if (type == (uint8_t)SN_FRAME_BLE_FILTER) {
		sn_radio_ble_set_filter(payload, len);
		return;
	}
	/* Keys ride in a frame for the same reason the filter does, and are
	 * likewise not answered. radio_ble.c logs a refusal. */
	if (type == (uint8_t)SN_FRAME_BLE_KEYS) {
		(void)sn_radio_ble_set_keys(payload, len);
		return;
	}
	if (type != (uint8_t)SN_FRAME_CONTROL_CMD) {
		return;
	}
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
		/* The radio left behind is stopped. It kept running, and its
		 * frames reached a host decoding them as the other radio's. */
		if (value != selected_radio) {
			(void)stop_radio(selected_radio);
		}
		selected_radio = (uint8_t)value;
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_SET_BLE_PHYS:
		/* 1 is the 1M PHY, 4 adds Coded, 0 is legacy scanning. Zero
		 * was refused, so the host's "Legacy only" could not open a
		 * capture on this board at all. */
		if (value > 0xFFu) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		ble_phys = (uint8_t)value;
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_SET_BLE_PERIODIC:
		/* Stored in the radio rather than here, because it is read on
		 * the path that sees each advertisement. */
		sn_radio_ble_set_periodic(value != 0u);
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
		/* The last channel's packets go now, not whenever the linger
		 * timer next fires. */
		sn_batch_flush();
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
		reply(command,
		      stop_radio(selected_radio) == 0 ? SN_STATUS_OK
						      : SN_STATUS_FAILED,
		      0u);
		break;

	case SN_CMD_GET_INFO:
		/* Every capture opens with this, so it starts a fresh session.
		 * This board does not reboot when its port opens, as the C6 does,
		 * so without it a second capture carried the first one's counts
		 * -- 104 frames written up as "509 received" -- and the last
		 * capture's PHY choice. */
		/* And from nothing running. A session that ended without a
		 * STOP -- a killed capture -- left its radio going, and its
		 * syncs with it, into this one. */
		(void)stop_radio(RADIO_154);
		(void)stop_radio(RADIO_BLE);
		sn_link_reset_counters();
		sn_batch_reset_counters();
		sn_radio154_reset_counters();
		sn_radio_ble_reset_counters();
		/* Every setting back to its default, not only the PHY:
		 * periodic following and the scan timing carried over too, and
		 * a host that sent them only when set could not undo them. */
		ble_phys = 1u;
		ble_interval_ms = 0u;
		ble_window_ms = 0u;
		sn_radio_ble_set_periodic(false);
		(void)set_antenna(0u);
		/* The host refuses to open a capture until this matches
		 * EXPECTED_FIRMWARE_VERSIONS["nrf54l15"], because an older
		 * board packs its metadata differently and every field would
		 * then decode to a confident wrong number rather than an
		 * error. */
		reply(command, SN_STATUS_OK, sn_firmware_version());
		break;

	case SN_CMD_SET_ANTENNA: {
		/* It refused the external antenna, which the host offers
		 * because the board has the switch, so choosing it made the
		 * capture fail to open. */
		const int err = set_antenna(value);

		reply(command,
		      err == 0 ? SN_STATUS_OK
			       : err == -EINVAL ? SN_STATUS_BAD_VALUE
						: SN_STATUS_FAILED,
		      value);
		break;
	}

	case SN_CMD_ENERGY_DETECT: {
		/* Packed as the ESP32-C6 packs it: channel in the low byte,
		 * the window in 16 us symbols above it. This was refused as
		 * unknown until the survey was ported from Nordic's
		 * 802154_phy_test, and the nRF README listed "no spectrum
		 * survey" among this board's limitations.
		 *
		 * An 802.15.4 measurement, so refused while BLE is selected,
		 * for the reason SET_CHANNEL is: the host and the board
		 * disagreeing about the radio deserves a refusal rather than
		 * a measurement taken on the wrong one. */
		if (selected_radio == RADIO_BLE) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}

		int8_t dbm = 0;
		const int err = sn_radio154_energy_detect(
			(uint8_t)(value & 0xFFu), value >> 8, &dbm);

		if (err == -EINVAL) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		if (err != 0) {
			LOG_WRN("energy detection on %u failed: %d",
				(unsigned)(value & 0xFFu), err);
			reply(command, SN_STATUS_FAILED, value);
			break;
		}
		/* Signed, so widened through uint8_t for the host to
		 * reinterpret -- exactly as the C6 replies. */
		reply(command, SN_STATUS_OK, (uint32_t)(uint8_t)dbm);
		break;
	}

	default:
		reply(command, SN_STATUS_UNKNOWN_COMMAND, 0u);
		break;
	}
}
