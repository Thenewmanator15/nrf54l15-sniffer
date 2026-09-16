# nrf54l15-sniffer

Passive IEEE 802.15.4 capture on a Seeed XIAO nRF54L15, streaming into
Wireshark. **Nothing here transmits.**

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
west flash -d G:\dev\scratch\nrf\bcap --runner openocd
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
