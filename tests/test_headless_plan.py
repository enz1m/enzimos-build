# SPDX-License-Identifier: MIT
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from headless_plan import (
    DELIVERY, DESKTOP_INTEGRATION, DESKTOP_PREVIEW, FLATPAK, FOUNDATION,
    GAMING, HARDWARE, CLI_ESSENTIALS, LOGIN_PERSONALIZATION, DEVELOPER_OPTIONAL,
    RDP_BUILD_OPTIONAL, RDP_RUNTIME_OPTIONAL,
    read_seed, parse_resolution, resolver_argv, check_empty_target,
)


HEADLESS_PACKAGES = {'base', 'linux', 'linux-lts', 'mkinitcpio', 'btrfs-progs',
                     'cryptsetup', 'limine', 'dosfstools', 'nano', 'dbus-broker-units'}
DESKTOP_PACKAGES = (FOUNDATION | HARDWARE | DESKTOP_PREVIEW | FLATPAK | GAMING |
                    DELIVERY | DESKTOP_INTEGRATION | CLI_ESSENTIALS | LOGIN_PERSONALIZATION |
                    {'plymouth', 'refind', 'efibootmgr', 'xdg-desktop-portal-hyprland',
                     'earlyoom'})


def seed_fixture(purpose, packages, repositories=('core', 'extra')):
    return {
        'schema_version': 1,
        'purpose': purpose,
        'architecture': 'x86_64',
        'repository_snapshot': '2000-01-01',
        'requested_packages': sorted(packages),
        'databases': [
            {'repository': name, 'file': f'{name}.db', 'bytes': 4, 'sha256': 'a' * 64,
             'server': f'https://archive.archlinux.org/repos/2000/01/01/{name}/os/x86_64'}
            for name in repositories
        ],
        'limitations': ['Synthetic test data; no database bytes or package acquisition.'],
    }


def listing(seed):
    base = seed['databases'][0]['server']
    return '\n'.join(f'{name}\t1-1\tany\tcore\t{base}/{name}-1-1-any.pkg.tar.zst\t123\t' + 'a' * 64
                     for name in seed['requested_packages']) + '\n'


class HeadlessPlanTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.seed_path = Path(temp.name) / 'seed.json'
        self.seed = self.read_fixture('v2-headless-experiment-not-product-payload', HEADLESS_PACKAGES)

    def read_fixture(self, purpose, packages, repositories=('core', 'extra')):
        self.seed_path.write_text(json.dumps(seed_fixture(purpose, packages, repositories)))
        return read_seed(self.seed_path)

    def read_desktop_fixture(self):
        return self.read_fixture('install-media-desktop-login-not-release-payload',
                                 DESKTOP_PACKAGES, ('core', 'extra', 'multilib'))

    def test_builder_seed_requires_broker_provider(self):
        seed = self.read_fixture('clean-build-closure-not-product-payload',
                                 {'base', 'base-devel', 'devtools', 'python', 'dbus-broker-units'})
        seed['requested_packages'].remove('dbus-broker-units')
        self.seed_path.write_text(json.dumps(seed))
        with self.assertRaises(Invalid):
            read_seed(self.seed_path)

    def test_seed_and_complete_resolution_are_not_authentication(self):
        seed = self.seed
        result = parse_resolution(listing(seed), seed)
        self.assertEqual(result['package_count'], 10)
        self.assertFalse(result['package_signatures_verified'])
        self.assertFalse(result['repository_signatures_verified'])
        self.assertFalse(result['package_bytes_downloaded'])
        self.assertFalse(result['offline_product_payload_complete'])
        self.assertFalse(result['release_authorized'])

    def test_optional_build_roots_cannot_be_admitted_to_the_default_seed(self):
        default = self.read_desktop_fixture()
        for purpose, packages, optional in (
            ('developer-setup-fixtures-not-product-payload', DEVELOPER_OPTIONAL, 'podman'),
            ('rdp-server-build-fixtures-not-product-payload', RDP_BUILD_OPTIONAL, 'freerdp'),
            ('rdp-server-runtime-fixtures-not-product-payload', RDP_RUNTIME_OPTIONAL, 'freerdp'),
        ):
            with self.subTest(purpose=purpose):
                seed = self.read_fixture(purpose, packages)
                self.assertIn(optional, seed['requested_packages'])
                self.assertNotIn(optional, default['requested_packages'])
                with tempfile.TemporaryDirectory() as temp:
                    path = Path(temp) / 'seed.json'
                    for extra in ('docker', 'kcmutils', '--root=/'):
                        invalid = copy.deepcopy(seed)
                        invalid['requested_packages'].append(extra)
                        path.write_text(json.dumps(invalid))
                        with self.assertRaises(Invalid):
                            read_seed(path)
                    seed['purpose'] = default['purpose']
                    path.write_text(json.dumps(seed))
                    with self.assertRaises(Invalid):
                        read_seed(path)

    def test_seed_cannot_inject_flags_sources_or_wrong_boot_provider(self):
        original = self.seed
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'seed.json'
            for mutate in (lambda s: s['requested_packages'].append('--root=/'),
                           lambda s: s['requested_packages'].remove('linux-lts'),
                           lambda s: s['databases'][0].update(server='file:///private'),
                           lambda s: s['databases'][0].update(file='../core.db'),
                           lambda s: s.update(schema_version=True)):
                seed = copy.deepcopy(original);mutate(seed);path.write_text(json.dumps(seed))
                with self.assertRaises(Invalid):
                    read_seed(path)

    def test_desktop_parity_requires_reviewed_recording_provider(self):
        original = self.read_desktop_fixture()
        self.assertIn('wf-recorder', original['requested_packages'])
        self.assertIn('wayvnc', original['requested_packages'])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'seed.json'
            for packages in [set(original['requested_packages']) - {provider}
                             for provider in ('wf-recorder', 'wayvnc', 'orca', 'speech-dispatcher',
                                              'espeak-ng', 'at-spi2-core', 'unicode-emoji', 'grim', 'slurp', 'libpulse',
                                              'cups', 'cups-filters', 'ghostscript', 'cups-pk-helper', 'ipp-usb', 'avahi',
                                              'sshfs', 'smbclient', 'libmtp', 'ifuse', 'openssh', 'networkmanager-openvpn',
                                              'networkmanager-openconnect', 'accountsservice', 'python-pillow')]+[
                             set(original['requested_packages']) | {'unreviewed-recorder'}]:
                seed = copy.deepcopy(original)
                seed['requested_packages'] = sorted(packages)
                path.write_text(json.dumps(seed))
                with self.assertRaises(Invalid):
                    read_seed(path)

    def test_resolution_rejects_path_escape_invalid_counts_and_metadata(self):
        seed = self.seed;good = listing(seed)
        variants = [good + good, good.replace('https://archive.archlinux.org/', 'https://example.invalid/'),
                    good.replace('/base-1-1-any.pkg.tar.zst', '/../base-1-1-any.pkg.tar.zst'),
                    good.replace('\tany\t', '\taarch64\t'), good.replace('\t123\t', '\t-1\t'),
                    good.replace('a' * 64, 'not-a-hash'), '\n'.join(good.splitlines()[1:])]
        extra = good.splitlines()[0].replace('base', 'grub')
        variants.append(good + extra + '\n')
        for text in variants:
            with self.assertRaises(Invalid):
                parse_resolution(text, seed)

    def test_empty_database_version_marker_is_not_an_installed_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'db/local').mkdir(parents=True)
            (root / 'cache').mkdir()
            check_empty_target(root)
            (root / 'db/local/ALPM_DB_VERSION').write_text('9\n')
            check_empty_target(root)
            (root / 'db/local/some-package').mkdir()
            with self.assertRaises(Invalid):
                check_empty_target(root)
            (root / 'db/local/some-package').rmdir()
            (root / 'cache/unexpected.pkg').write_text('not allowed')
            with self.assertRaises(Invalid):
                check_empty_target(root)

    def test_no_refresh_download_install_or_host_database(self):
        seed = self.seed
        args = resolver_argv(Path('/verified/root'), Path('/new/private/plan'), seed)
        self.assertIn('--unshare-all', args)
        self.assertIn('--print', args)
        self.assertNotIn('--refresh', args)
        self.assertNotIn('--downloadonly', args)
        self.assertNotIn('/var/lib/pacman', args)
        self.assertEqual(args[args.index('--config') + 1], '/tmp/plan/pacman.conf')
        self.assertEqual(args[args.index('--ro-bind') + 1:args.index('--ro-bind') + 3], ['/verified/root', '/'])


if __name__ == '__main__':
    unittest.main()
