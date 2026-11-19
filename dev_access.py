# SPDX-License-Identifier: MIT
"""Development builds only: key-only SSH (and mDNS) into the live installer and the
installed system, so a test install on real hardware can be followed remotely.

Enabled by ENZIMOS_DEV_SSH_KEY=<public key file> at build time; release media never
carry it. Root may log in with that key only; passwords are refused."""
import os
from pathlib import Path

SSHD = """# enzimOS development build: key-only SSH for remote debugging. Never in release media.
Port 22222
AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/enzimos-dev-authorized-keys
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
"""

FIREWALL = """[Unit]
Description=enzimOS development build: allow SSH through the firewall
After=firewalld.service
Wants=sshd.service

[Service]
Type=oneshot
# Compatibility for an already-running firewall. The shipped policy also keeps
# access available after a later firewall start, reload or network-zone change.
ExecStart=-/usr/bin/firewall-cmd --add-port=22222/tcp
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""

DEV_POLICY = """<?xml version="1.0" encoding="utf-8"?>
<policy target="CONTINUE" priority="-300">
  <short>enzimOS development SSH</short>
  <description>Key-only debugging access on development media only.</description>
  <ingress-zone name="ANY"/>
  <egress-zone name="HOST"/>
  <port port="22222" protocol="tcp"/>
</policy>
"""


def key():
    """The public key from ENZIMOS_DEV_SSH_KEY, or None for a normal build.
    A release build (ENZIMOS_RELEASE set) refuses one."""
    path = os.environ.get('ENZIMOS_DEV_SSH_KEY')
    if not path:
        return None
    if os.environ.get('ENZIMOS_RELEASE'):
        raise ValueError('a release build refuses ENZIMOS_DEV_SSH_KEY')
    text = Path(path).read_text().strip()
    if '\n' in text or not text.startswith('ssh-ed25519 '):
        raise ValueError('ENZIMOS_DEV_SSH_KEY must name one ssh-ed25519 public key')
    return text


def apply(root, public_key):
    """Write dev SSH access into a root tree (live root or the installed desktop stage)."""
    root = Path(root)
    def write(rel, text, mode=0o644):
        p = root/rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        p.chmod(mode)
    def want(unit):
        link = root/'etc/systemd/system/multi-user.target.wants'/unit
        link.parent.mkdir(parents=True, exist_ok=True)
        if link.is_symlink() or link.exists():
            link.unlink()
        target = root/'usr/lib/systemd/system'/unit
        link.symlink_to(f'/usr/lib/systemd/system/{unit}' if target.exists() else f'/etc/systemd/system/{unit}')
    write('etc/ssh/sshd_config.d/90-enzimos-dev.conf', SSHD)
    write('etc/ssh/enzimos-dev-authorized-keys', public_key + '\n')
    write('etc/systemd/system/enzimos-dev-access.service', FIREWALL)
    write('etc/firewalld/policies/enzimos-dev-ssh.xml', DEV_POLICY)
    write('etc/enzimos-dev-access', 'This is an enzimOS development build with key-only SSH access on port 22222 for debugging.\n')
    want('sshd.service')
    want('enzimos-dev-access.service')
    if (root/'usr/lib/systemd/system/avahi-daemon.service').exists():
        want('avahi-daemon.service')
