# Default gaming image acceptance

Run after the canonical firstboot checks on a freshly installed encrypted image.
The test payload supplies exactly nine SHA-256 bindings as `policy-hashes.json`.
No OS overlay, optional package, Steam runtime or controller emulator is installed.
A real normal admin login is required for the user manager and active-seat access
checks. The test verifies the signed controller package, default modules, absence
of optional gaming apps, effective system/user slices, inference priority, actual
uinput access and another account's denial. It then powers off.
