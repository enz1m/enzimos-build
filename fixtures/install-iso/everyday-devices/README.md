# Everyday devices installed acceptance

These files are explicit disposable-guest test payloads, not shipping services.
Use an eligible encrypted UEFI first boot result from the expanded desktop seed.
Run one VM at a time with the workspace resource lock, one CPU, 4 GiB guest RAM,
no external network, and the existing installer VNC tool for native input. The
VM harness owns QMP; never open a second connection.

`run.sh` runs real local CUPS, NetworkManager WireGuard/OpenVPN and connectivity
tests, and checks that enzimos-mount (D-117) is installed, registered and enabled
with the session while GVfs's SMB/MTP backends and metadata daemon are absent.
Network share, phone and drive flows need an active local login (polkit
`allow_active`), so they are qualified in the dedicated mount VM
(`tools/mount_vm.py check`), not by this root-driven payload. Fixture-only Samba and WireGuard tooling must come from the
same reviewed signed snapshot. `fixture-packages.json` records their exact
filenames and hashes; pacman also verifies signatures. Keys, passwords and test
servers exist only inside disposable guest RAM. The Samba fixture adds a narrowly
scoped vendor AppArmor site include for that RAM directory; server confinement
stays enforced. No such exception is shipped. Production never enables an SSH
or SMB server. Failures and clean shutdown remain part of the result.

`gui_check.py` additionally needs a normal logged-in native desktop and a compiled
`portal-client` test executable on the payload. It tests real native polkit
cancellation/approval and Print-portal cancellation/submission through a restricted
Flatpak peer, without its CUPS socket or network access. Using Zen's installed
runtime for this explicit test client does not qualify Zen's own print menu.
After normal native login, open the native Terminal with Super+Enter. Run the
exact `gui_client.py` command printed by each READY marker (`deny`, `allow`,
`cancel`, `print`) and operate the corresponding real dialog through VNC.
Do not run these clients through a root service's `runuser`: that process is outside
the login session and polkit correctly refuses it. Review screenshots before
claiming GUI acceptance. The fixture cannot manufacture user approval.

The backend gates include PostScript/PDF/raster conversion and actual IPv4/IPv6
multicast packet checks across public/trusted firewall zones. SSH host-key refusal
and replacement are part of the mount VM qualification.

These tests do not qualify physical Android MTP, USB printer firmware, real Wi-Fi
capture portals, VPN OTP, remote VPN certificate replacement or the Files/Settings
frontend. Record those separately; a backend marker is not an end-to-end device
or product UI claim.

`settings.sh` / `settings_check.py` are the manual native Settings printer gate.
The payload must retain the companion `check.py` backend and `sharing.test`; no
extra test server package is needed. Start a normal desktop, find Printers and
Search. Cancel Add approval and, after reviewing the refusal, acknowledge in the
native Terminal with `touch /home/admin/printer-denial-reviewed`. Retry Add with
real administrator approval, Pause and print a test page. The fixture separately
queues a root-owned dummy job; review that only one own job and its count appear,
then `touch /home/admin/printer-privacy-reviewed`. Cancel that own job through
Settings, Resume and Remove the printer. After reviewing the empty final list,
`touch /home/admin/printer-final-reviewed`. Markers never substitute for actual
UI review. Live IPP must report sharing false; printable lpoptions defaults or
an immediately saved configuration file are insufficient proof. The native
queue gate does not qualify physical hardware, print-option dialogs or a changed
default image. IPP syntax: [CUPS ipptoolfile documentation](https://openprinting.github.io/cups/doc/man-ipptoolfile.html).
