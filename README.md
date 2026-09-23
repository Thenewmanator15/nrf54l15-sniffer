# nrf54l15-sniffer

Passive capture on a Seeed XIAO nRF54L15, streaming into Wireshark: IEEE
802.15.4 (Zigbee, Thread, Matter) and Bluetooth LE advertising, including
periodic advertising trains. **Nothing here transmits.**

This is firmware only. The Wireshark plugin that reads it lives in
[esp32c6-sniffer](https://github.com/Thenewmanator15/esp32c6-sniffer) and
speaks to both boards, so install it from there — one plugin, whichever board
you have.

The framing is a submodule:
[sniffer-wire-format](https://github.com/Thenewmanator15/sniffer-wire-format),
whose `frame.c` is compiled by the ESP32-C6 firmware too, so the two boards
cannot drift from each other. Clone with it:

```bash
git clone --recurse-submodules https://github.com/Thenewmanator15/nrf54l15-sniffer
```

An existing clone catches up with `git submodule update --init`.

## State

**Both work.** The framing is held to the golden vectors by the same test that
holds the ESP32-C6, and 802.15.4 capture reaches Wireshark -- 113 frames in 15
seconds on a live Zigbee network, channel 25.

Capture was blocked for a long time by a fault that is not in this firmware:
the radio driver's RX thread overflows its default stack, silently, and only
when something else on the board logs. Read
[docs/2026-09-14-nrf54l15-spike.md](docs/2026-09-14-nrf54l15-spike.md) before
concluding the radio is broken again -- it is the first thing to suspect, and
it cost several nights the first time.

## Limitations

Most of these are the board rather than the firmware, and none of them is a
plan to fix something. They are here so nobody spends an evening finding one
out.

**Two radios, not three.** IEEE 802.15.4, channels 11 to 26, and Bluetooth LE
advertisements. Wi-Fi does not exist on this part and is *refused* when the
host asks for it, rather than accepted and quietly ignored.

**BLE here is a scanner, not a link-layer sniffer.** Advertisements, scan
responses, and the periodic trains that carry Auracast; never a connection,
which needs link-layer access the controller does not expose over HCI. Two
further ceilings, neither of them configuration:

- **One periodic sync at a time.** `CONFIG_BT_PER_ADV_SYNC_MAX` defaults to 1
  and `prj.conf` does not raise it, so one is what the SoftDevice Controller
  is built with. Asking for a second produces a refusal and nothing else.
- **No direction finding.** The SoftDevice Controller offers
  `sdc_support_le_connectionless_cte_transmitter` and no receiving
  counterpart, so AoA and AoD are out whatever antenna is attached.

What this board has and the ESP32-C6 does not is LE Audio. A periodic train
carrying a broadcast also carries BIGInfo, and this firmware asks the
controller to join the isochronous group it describes and forwards the audio
as ISO packets. The C6's silicon has no isochronous channels at all, so it can
name a broadcast and never hear it.

**Not yet seen working on air.** Until 2026-09-24 the forwarding dropped every
ISO packet: it typed each buffer with Zephyr's `bt_buf_get_type()`, since
deprecated, which assumes a buffer is outgoing, so an incoming ISO packet was
never recognised as one. That is fixed. Proving it needs a second LE Audio
broadcaster, and this bench has none: the XIAO is its only part with
isochronous channels.

**The link is a UART, not USB, and it is the ceiling.** The nRF54L15 has no USB
device controller, so the host is reached through the board's SAMD11 bridge.
Measured end to end: **94.3 kB/s**, against roughly **810 kB/s** for the
ESP32-C6 over real USB. That is the single biggest difference between the two
boards. 1 Mbaud is the UARTE's ceiling on this part, so it cannot simply be
raised; the overlay in `boards/` fixes it there and the plugin already matches.

**The bridge drops bytes, and nothing on this side of it can stop that.** The
SAMD11 holds at most 319 bytes on their way to USB. When its USB side pauses --
for several milliseconds, and below anything the host application does; a bare
read loop sees the same -- the rest of any continuous burst past 319 bytes is
thrown away. Measured with BLE capture at 58 records/s beside an ESP32-C6
advertising every 30 ms: 14 frames lost their tails in a minute, 10 of them cut
at exactly 319 bytes delivered, 8.7% of every frame longer than that.

Loss follows how many bursts exceed 319 bytes, not how many packets there are.
At 30 records/s batches rarely grow that long and one frame was hit in a
minute; at 24 or fewer, none. A second, rarer fault drops a single byte at a
random position, about once a minute at full load.

Pacing was measured and not kept. Transfers stay capped at 64 bytes with a
20 us gap. Gaps of 500 and 1000 us roughly halved the overflow, and 1500 us
suppressed it for one two-minute run, but the pauses are long enough that
outlasting them takes the link down to about 30 kB/s -- below a saturated
802.15.4 channel -- and even that is not a guarantee.

What changed instead is what a loss costs. The header CRC covers only the
header, so a truncated frame used to decode with the start of the next frame as
its tail -- 6 of 13 damaged batches in one run were accepted as valid and
reached Wireshark -- and the frame after it was lost. The host's parser now
spots a header starting inside a payload, drops the damaged frame and resumes at
the one that followed. Replaying every recorded dump, 34 of 34 truncations were
caught and none delivered; live, 9 of 9, each costing exactly one counted frame.
The nRF54LM20 has USB of its own, and no bridge at all.

**The bridge also carries leftovers from one session into the next.** When the
port closes with data in flight, the SAMD11 keeps the whole 64-byte USB packets
it had queued -- the frame they belong to cut at a packet boundary, a 143-byte
batch arriving as 128 -- and releases them in front of whatever the board sends
next. Opening a session, that is the reply to `GET_INFO`, which the stale
frame's missing tail swallowed: half the opens after a loaded capture, and the
first after a reflash, timed out with a healthy board. Waiting before asking
does not help, since the leftovers come out only when the board next transmits.
The host instead asks again if the first answer has not come within half a
second, by which time that answer has pushed the leftovers out.

**Per-packet overhead is 22 bytes, and batching only helps when traffic is
dense.** A packet sent on its own costs a 10-byte frame header and 12 bytes of
metadata, so a 5-byte acknowledgement travels as 27. Packets that arrive within
20 ms of each other are combined into one `PACKET_BATCH`, which shares a single
header and delta-codes the timestamps: a full batch of 32 costs about 5.6 bytes
per packet instead of 22.

The catch is that a quiet channel produces no batches worth the name. On this
bench most packets arrive alone and are sent alone -- a batch of one would be
*larger* than a plain `PACKET`, so the firmware sends a `PACKET` instead. The
saving is therefore real on a busy channel and zero on an idle one, which is
the opposite of when a sniffer is under pressure but the same direction as
where the bytes actually are.

**Frames that fail their checksum never arrive.** The driver validates and
strips the FCS before this firmware sees anything, so a capture cannot show
malformed or corrupted frames -- only that a gap exists where one might have
been. PSDUs are capped at 127 bytes, which is the standard's own limit.

**The onboard antenna only.** The board has an RF switch, but which position
selects which antenna is not established and the gain difference has not been
measured, so asking for the external antenna is refused rather than accepted
and ignored.

**No snaplen, no hardware filter, no trace.** The wire format carries commands
for all of these and the ESP32-C6 implements them; here they return
`SN_STATUS_UNKNOWN_COMMAND`.

**The energy survey is here, at millisecond resolution.** Ported from Nordic's
`802154_phy_test`, through Zephyr's radio API rather than the raw
`nrf_802154_*` calls that sample makes, because Zephyr's driver already owns
the callbacks those would need. The wire format asks for a window in 16 us
symbols and the driver measures in whole milliseconds, so the window is
rounded up: the host's 1250-symbol request is exactly 20 ms, but anything
under a millisecond is measured for one. A peak over a longer window can only
be higher, so the rounding errs toward calling a channel busy. A capture in
progress is suspended for the measurement and resumed on its own channel, and
any frame heard while the radio was tuned away is dropped rather than recorded
against the wrong channel.

**Drop accounting is partial.** Frames refused because the outbound ring was
full are counted and reported, as is the ring's depth and the high-water mark
it reached -- drops say what was lost after the fact, depth says whether loss
is coming. Short writes and transmit stalls are always reported as zero,
because this link cannot detect them: reporting anything else would invent a
measurement, and a zero meaning "none" is indistinguishable from a zero meaning
"cannot tell".

The same applies to three of the eleven BLE counters. There is no intermediate
receive queue here to overflow, and `send_command` does not wait for the
controller to answer, so queue-full and command-timeout figures go out as
zeros that mean "cannot tell" rather than "none". The header says which.

**Timestamp accuracy is uncharacterised.** Timestamps come from the driver's
own packet timestamp at microsecond resolution. The ~0.5 us figure measured on
the ESP32-C6, against the standard's fixed acknowledgement turnaround, has not
been reproduced on this board. Do not quote it for this one.

**Reception is unsupported by Nordic and has been layout-sensitive.** Their
position, at the time of writing:

> There is currently no support for using nRF54L15 as a sniffer, though that
> is a request that Nordic is looking into, but they cannot promise or provide
> a timeline for this.

Two binaries with byte-identical Kconfig were observed to behave differently.
`CONFIG_IEEE802154_NRF5_RX_STACK_SIZE=2048` is load-bearing rather than a
tuning choice: the driver's RX thread defaults to 800 bytes and was measured at
792 used, and anything that grows it stops reception **silently** -- start
returns success, the channel reads back, promiscuous reads back true, and no
frame ever arrives. If frames stop after an unrelated change, read
[docs/2026-09-14-nrf54l15-spike.md](docs/2026-09-14-nrf54l15-spike.md) before
suspecting anything else.

**The plugin is in another repository.** Its firmware-version check therefore
spans two repositories: if a capture is refused for a version mismatch, take a
newer hex from this repository's releases rather than assuming the plugin is
wrong.

**It transmits nothing.** Auto-acknowledgement is off and the radio is in
promiscuous receive. That is a design constraint, not an omission -- there is
no active scan, no injection and no association.

## Toolchain

nRF Connect SDK **v3.4.0** (Zephyr 4.4.0, west 1.5.0), installed with
`nrfutil sdk-manager`. openocd is **not** part of it and must be installed
separately -- `winget install xpack-dev-tools.openocd-xpack`.

Set up the environment once per shell:

```powershell
nrfutil sdk-manager toolchain env --ncs-version v3.4.0 --as-script powershell | Out-File ncsenv.ps1
. .\ncsenv.ps1
```

## Build and flash

The board target needs its SoC and cpucluster qualifiers. A bare
`xiao_nrf54l15` does not resolve.

```powershell
$env:ZEPHYR_BASE = "C:\path\to\ncs\v3.4.0\zephyr"   # your NCS workspace
cd $env:ZEPHYR_BASE\..                             # west must run inside it
west build --no-sysbuild -b xiao_nrf54l15/nrf54l15/cpuapp -d G:\dev\scratch\nrf\bcap <this directory> --pristine -- -DSN_MODE=2
west flash -d G:\dev\scratch\nrf\bcap --runner openocd --verify
```

**`west build` must run inside the west workspace.** `ncsenv.ps1` does not set
`ZEPHYR_BASE`, and outside the workspace the error names neither it nor the
directory, it only says

    west: unknown command "build"; do you need to run this inside a workspace?

**openocd is not on `PATH` after `winget install`.** It stays in the WinGet
package store, so `west flash` reports only `required program openocd not
found` until it is added by hand:

    $env:PATH = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\" +
        "xpack-dev-tools.openocd-xpack_Microsoft.Winget.Source_8wekyb3d8bbwe\" +
        "xpack-openocd-0.12.0-7\bin;$env:PATH"

**Keep the build directory short.** Zephyr appends a deep
`zephyr/include/generated/...` tree, and a long build path pushes the real
paths past Windows' 260-character `MAX_PATH`. The failure is not obvious: it
surfaces inside `dts_edt_pickle` as

    1: "Abnormal exit with child return code: no such file or directory"

`LongPathsEnabled=1` in the registry does not help, because Zephyr's `dtc` and
Python helpers do not opt in through their manifests.

**openocd is the only runner that works here.** `jlink` and `nrfjprog` need a
SEGGER probe; this board has a SAMD11 running CMSIS-DAP. `nrfutil` can see the
board -- `nrfutil device list` names it -- but enumerates it as a serial device
with no programming trait, and fails with "Unable to find a board".

**On NCS v3.4.0, openocd leaves the end of the image unwritten.** The board's
`nrf54l-load` turns on the RRAM controller's one-line write buffer (16 bytes)
and never commits it, so the reset that follows discards the image's last
partial line -- up to 15 bytes, whatever the previous firmware left there
stays. The linker puts the tail of `.data` last, so what breaks depends on the
build. Zephyr's Bluetooth samples lose a buffer pool's pointer and fault in
`net_buf_alloc_len` at boot. This firmware loses the pointers of the
networking stack's transmit pool, which a receive-only build never allocates
from: it runs by luck, not by design. Measured by writing `deadbeef` over the
line and flashing again: all 12 tail bytes stayed `deadbeef`.

Zephyr fixed it upstream in commit
[1079b21](https://github.com/zephyrproject-rtos/zephyr/commit/1079b21). On
v3.4.0, add the same line to `nrf54l-load` in
`zephyr/boards/seeed/xiao_nrf54l15/support/openocd.cfg`:

    proc nrf54l-load {file} {
    	mww 0x5004b500 0x101
    	load_image $file
    	mww 0x5004b008 1    ;# RRAMC TASKS_COMMITWRITEBUF
    }

`--verify` resets the board before it compares, so it catches an unpatched
SDK: the mismatch it reports is the last line of the image.

## SN_MODE

Mirrors the ESP32-C6 firmware's, so both boards are driven the same way.

| Mode | What it does |
|---|---|
| 0 | Conformance burst. The default, and what the host test suite needs. |
| 2 | Capture. |

## Testing

The test suite lives with the plugin, in
[esp32c6-sniffer](https://github.com/Thenewmanator15/esp32c6-sniffer). With
this board attached and a conformance build (`-DSN_MODE=0`) flashed, run from
that repository's `host/`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_conformance.py -v -m hardware --port COM4 --baud 1000000
```

No test code is specific to this board. The suite takes a `--port` and does
not care which firmware is behind it, which is the point: one set of golden
vectors holds both boards.

## Rules for the shared source

`shared/frame.c` and `shared/commands.h` come from the submodule and are
compiled into both firmwares and must depend on nothing but `<stddef.h>`, `<stdint.h>` and
`<string.h>`. Adding an SDK header to either breaks the other board's build --
which is the mechanism working, not failing.

## Why there is no USB in prj.conf

The nRF54L15 has no USB device controller; within the nRF54L family that is
the LM20A and LM20B only. The host is reached through the SAMD11's USB CDC
bridge over `uart20`. Nordic's own `802154_sniffer` sample configures CDC-ACM
directly and cannot run on this part for exactly that reason.

`uart20` defaults to 115200 baud, about 11.5 kB/s. An 802.15.4 channel can
produce roughly 31 kB/s, so that default is not merely slow, it is
insufficient for capture. It is raised to 1 Mbaud -- the UARTE's ceiling on
this part -- by the overlay in `boards/`, which the host must match; the
extcap does, from the `baud` field in its `BOARDS` table.

That measures 94.3 kB/s end to end, 94% of line rate, using EasyDMA rather
than per-byte `uart_poll_out`. The numbers and how they were taken are in
[docs/2026-09-14-nrf54l15-spike.md](docs/2026-09-14-nrf54l15-spike.md).

## Why the console and shell are off

There is one UART and the capture stream owns it. Anything else writing to it
puts unframed bytes into the data path, which is what
`test_no_unframed_bytes_once_synchronised` exists to catch.
