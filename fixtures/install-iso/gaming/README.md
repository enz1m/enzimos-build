# Installed gaming fixture

Authored MIT diagnostic programs; no game, Windows SDK, model, credentials or
Proton binary is tracked here. Run only in an explicitly disposable installed VM.
`uinput.py` creates a virtual controller and must never be run on the host.

The root fixture installs reviewed, signed optional package deltas and a signed
Flathub Steam export, applies an explicit OS-policy overlay and waits for a real
normal graphical login. It tests active-seat uinput access and a negative second
account. Each client runs from the native Terminal as the normal user; the root
fixture accepts bounded result files owned by that user. `run.sh` powers the VM
off on either pass or failure.

## Payload inputs

Prepare the usual `install_iso_vm` testpayload with these files:

- `run.sh`, `check.py`, `client.py`, `uinput.py` from this directory.
- `packages/` and `package-inventory.json`: only needed signed Arch packages from
  a separately reviewed and resolved gaming seed, plus the
  default profile's signed `steam-devices`; each inventory entry has filename
  and SHA-256. Do not disable package signature checks.
- `os-integration/`: the nine paths in `build_install_iso.GAMING_STAGE_FILES` from
  the owned desktop policy root. This is an explicit private overlay, not a new
  default-image acceptance claim.
- `flathub.flatpakrepo`, `steam-repo/` (signed offline collection repository),
  `steam-commit` (exact installed application commit).
  The collection must also contain exact signed `org.freedesktop.Platform.GL.default`
  and `GL32.default` refs for Steam's runtime branch. The fixture explicitly installs
  these related graphics extensions and checks each installed commit against its
  readonly collection ref; app-only offline installation can omit them.
- `gameprobe`, `abi32`, `mfprobe.exe`, `av.mp4`, `model.gguf`.
- A maintained GE-Proton release archive and `proton-artifact.json` with its
  filename and verified official API SHA-256. No execution on the host; no EOL
  Flathub Proton extension as a current-version substitute.

Only phases selected in `modes.json` copy their own probe/model/Proton inputs.
A Steam bootstrap-only payload needs none of the model, GE archive or probe binaries.
Large fixtures use `/var/tmp/enzimos-gaming-lab`, not the RAM-backed `/run` mount.
The VM needs explicit disk headroom; keep the harness's free-space guard.

## Building the authored probes

On a development machine with the matching compilers/headers:

```sh
cc -O2 -Wall -Wextra -Werror gameprobe.c $(pkg-config --cflags --libs sdl2) -lm -o gameprobe
cc -m32 -O2 -Wall -Wextra -Werror abi32.c -ldl -o abi32
llvm-dlltool -m i386:x86-64 -d kernel32.def -l kernel32.lib
clang --target=x86_64-pc-windows-msvc -fno-stack-protector -fno-builtin -O1 -Wall -Wextra -Werror -c mfprobe.c -o mfprobe.obj
lld-link /entry:mainCRTStartup /subsystem:console /nodefaultlib /out:mfprobe.exe mfprobe.obj kernel32.lib
```

`kernel32.def` is an authored import-name list. The Windows probe has no SDK or CRT
payload. `av.mp4` is the authored two-second H.264/AAC fixture, 320×180, 12 fps / mono 48 kHz.
`mf-reference.h` contains 16 luma samples from its decoded first frame. The
source-reader probe requires decoded raw video/audio samples, not compressed
packet counts. It verifies first-frame reference pixels (small decoder rounding
tolerance), aligned video buffers and signed PCM activity, excluding a blank
placeholder from a decoder pass. It tests direct maintained Proton Wine components within the
Steam runtime, not a commercial game or the full Valve Proton launcher.

## Optional online Steam first launch

An explicit `modes.json` selecting `steam-native` and `steam-flatpak` is an online
fixture, requiring the VM harness's explicit `network=True, internet=True` and VNC boot. The printed client
command launches the real client and waits for a manual review marker. Only after
capturing and reviewing the actual anonymous sign-in window, use another native
Terminal to `touch` the printed marker path. Do not sign into an account, buy a
game, or write the marker before review. The client checks ownership and a live
launcher, then shuts down only its own fixture client. This is first-launch
acceptance, not commercial-game or Proton-launcher acceptance.

With an already-qualified new default image, `policy-already-installed` makes the
fixture compare every supplied policy hash to installed bytes instead of copying
an overlay. Optional packages and Steam remain private test-only installations. `--network`
alone is isolated Ethernet and cannot download the Steam client; `--internet` is
a separate explicit outbound NAT option with no inbound forwarding.

## Native review

After each `ENZIMOS_GAMING_READY` marker, enter the printed client command in the
real native Terminal. For `native`, `flatpak` and `load`, capture and inspect the
actual SDL window, focus it, and press Space through VNC. No invented input
acknowledgement/result file. An explicit `modes.json` list can select only the
remaining runtime checks; it produces `ENZIMOS_GAMING_SELECTED_PASS`, never a full
fixture pass or an inference/copy claim for omitted phases. An explicit
`flatpak-display.json` containing `"x11"` prints a client command ending in `x11`
and tests only that compatibility path; it does not qualify Wayland or change
production environment/settings. The load phase first starts inference and waits 20
seconds before opening the rendering consumer. The result includes real virtual
controller transitions and PipeWire/Pulse audio callbacks. A null sink is used;
this does not certify physical speakers or headsets.

The load phase runs a private, opt-in 4,096-token calibration and a copy in
`background.slice`. It preserves production enrollment/configuration, checks the
copy digest and terminates its own transient units on cleanup. The model is a
private test input, not default installer content.

Physical gaming compatibility requires separate device and installed-system tests.
