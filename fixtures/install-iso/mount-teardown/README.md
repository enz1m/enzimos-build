# Installer mount teardown controls

Run only in a disposable guest. Place the exact reviewed installer
`mount_teardown.py` beside `check.py`, then enter a private mount namespace:

```sh
ENZIMOS_DISPOSABLE_TEST=1 unshare --mount --propagation private python3 -I check.py
```

The fixture refuses the initial namespace and an already mounted target. It
creates a 1 MiB tmpfs at the fixed installer target and holds its directory open
in a controlled child. A temporary holder must exit and permit normal unmount;
a persistent holder must produce refusal after the bounded deadline and remain
mounted until the fixture releases its own child. No lazy unmount, forced
unmount or signalling of other processes is used. The diagnostic must identify
the actual holder PID without printing credentials or argv.

This is an explicit native control, not part of host unit-test discovery.
