# SPDX-License-Identifier: MIT
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from native_apps_payload import COMPONENTS, GREETD_FILES, ICON_THEME_FILES, PORTAL_FILES, KEYRING_FILES, REPLACES, stage


class NativePayload(unittest.TestCase):
    def fixture(self, root, component='store', case=None, version='0.1.0'):
        name, status, executable = COMPONENTS[component]
        package = root/'native.pkg.tar.zst'; body = b'fixture native executable'
        identity = 'wrong' if case == 'identity' else name
        info = f'pkgname = {identity}\npkgver = {version}-1\narch = x86_64\n'.encode()
        if component == 'dev-monitor' and case != 'unpaired-monitor':
            info += b'depend = enzimos-terminal>=0.1.0-2\n'
        replaced = REPLACES.get(component)
        if replaced:
            provider = 'oo7' if component == 'keyring' else replaced
            relations = {'provides': f'provides = {provider}=1.3.12', 'conflict': f'conflict = {replaced}', 'replaces': f'replaces = {replaced}'}
            info += ''.join(line+'\n' for key, line in relations.items() if case != 'no-'+key).encode()
            if component == 'greetd' and case != 'no-console-relations':
                info += b'provides = greetd-agreety=0.10.3\nconflict = greetd-agreety\nreplaces = greetd-agreety\n'
        identifying = 0o644 if component == 'icon-theme' else 0o755
        expected = {executable: {'sha256':hashlib.sha256(body).hexdigest(), 'mode':identifying}}
        members = [('.PKGINFO',info,0o644),(executable,body,identifying)]
        if component == 'icon-theme':
            icon = 'usr/share/icons/enzim/scalable/apps/io.github.enzui.Terminal.svg'
            data = b'<svg/>'
            icon_mode = 0o755 if case == 'theme-executable' else 0o644
            for path, mode in [*ICON_THEME_FILES.items(), (icon, icon_mode)]:
                if path == executable: continue
                expected[path] = {'sha256':hashlib.sha256(data).hexdigest(), 'mode':mode}
                members.append((path,data,mode))
        if component == 'dev-monitor':
            for label, path, mode in [('cli', 'usr/bin/devmon', 0o755),
                    ('systemd', 'usr/lib/systemd/user/enzimos-dev-monitor.service', 0o644),
                    ('bus', 'usr/share/dbus-1/services/org.enzimos.DevMonitor1.service', 0o644)]:
                if case == 'missing-monitor-'+label: continue
                data = b'fixture activation component'
                expected[path] = {'sha256':hashlib.sha256(data).hexdigest(), 'mode':mode}
                members.append((path,data,mode))
        if replaced:
            for path, mode in (GREETD_FILES if component == 'greetd' else KEYRING_FILES if component == 'keyring' else PORTAL_FILES).items():
                if case == 'missing-portal-file' and path.endswith('.portal'): continue
                if case == 'missing-keyring-pam' and path.endswith('pam_oo7.so'): continue
                if case == 'missing-keyring-helper' and path == 'usr/lib/oo7-daemon-login': continue
                if case == 'missing-console' and path == 'usr/bin/agreety': continue
                data = b'fixture portal file'
                expected[path] = {'sha256':hashlib.sha256(data).hexdigest(), 'mode':mode}
                members.append((path,data,mode))
        if case in ('configuration', 'wrong-configuration', 'executable-configuration'):
            config_path = 'etc/passwd' if case == 'wrong-configuration' else 'etc/mise/config.toml'
            config_mode = 0o755 if case == 'executable-configuration' else 0o644
            config_data = b'[settings]\nparanoid=true\n'
            expected[config_path] = {'sha256':hashlib.sha256(config_data).hexdigest(), 'mode':config_mode}
            members.append((config_path,config_data,config_mode))
        links = {'timer-link': ('usr/lib/systemd/system', 'timers.target.wants', 'enzimos-flatpak-update.timer', True),
                 'foreign-link': ('usr/lib/systemd/system', 'timers.target.wants', 'enzimos-flatpak-update.timer', False),
                 'session-link': ('usr/lib/systemd/user', 'enzui-session.target.wants', 'enzimos-mountd.service', True),
                 'default-target-link': ('usr/lib/systemd/user', 'default.target.wants', 'enzimos-mountd.service', True),
                 'system-service-link': ('usr/lib/systemd/system', 'multi-user.target.wants', 'enzimos-mount-boot.service', True)}
        link_path = None
        aliases = {'theme-link': 'io.github.enzui.Terminal.svg', 'theme-dir-link': '../apps/io.github.enzui.Terminal.svg',
                   'theme-escape-link': '../../../hicolor/scalable/apps/other.svg', 'theme-missing-link': 'missing.svg'}
        if case in aliases:
            link_path = 'usr/share/icons/enzim/scalable/' + ('mimetypes' if case == 'theme-dir-link' else 'apps') + '/utilities-terminal.svg'
            expected[link_path] = {'link': aliases[case]}
        if case in links:
            directory, wants, unit_name, own = links[case]
            unit = f'{directory}/{unit_name}'; data = b'[Unit]\n'
            expected[unit] = {'sha256':hashlib.sha256(data).hexdigest(), 'mode':0o644}
            members.append((unit,data,0o644))
            link_path = f'{directory}/{wants}/{unit_name}'
            expected[link_path] = {'link': '../' + unit_name if own else '../other.timer'}
        with tarfile.open(package, 'w:zst') as archive:
            for path, data, mode in members:
                if case == 'missing' and path == executable: continue
                member = tarfile.TarInfo(path); member.mode = mode; member.size = len(data)
                if case == 'mode' and path == executable: member.mode = 0o777
                if case == 'owner': member.uid = 1000
                archive.addfile(member, io.BytesIO(data))
                if case == 'duplicate': archive.addfile(member, io.BytesIO(data))
            if link_path:
                member = tarfile.TarInfo(link_path)
                member.type = tarfile.SYMTYPE; member.linkname = expected[member.name]['link']
                archive.addfile(member)
            if case in ('link','traversal','extra'):
                member = tarfile.TarInfo('../outside' if case == 'traversal' else 'usr/bin/extra')
                if case == 'link': member.type = tarfile.SYMTYPE; member.linkname = '/etc/passwd'
                archive.addfile(member, io.BytesIO())
        report = {'package_name':name, 'status':status, 'release':1, 'release_authorized':False,
            'package':str(package), 'sha256':hashlib.sha256(package.read_bytes()).hexdigest(), 'files':expected}
        if version != '0.1.0': report['version'] = version
        if component == 'dev-monitor': report['api_version'] = 1 if case == 'wrong-monitor-api' else 2
        if replaced and case != 'undeclared-replacement': report['replaces'] = replaced
        if case == 'foreign-replacement': report['replaces'] = 'systemd'
        if case == 'authorized': report['release_authorized'] = True
        if case == 'tamper': package.write_bytes(package.read_bytes()+b'changed')
        path = root/'build.json'; path.write_text(json.dumps(report)); return path

    def test_each_native_component_full_inventory_and_identity(self):
        for component in COMPONENTS:
            with self.subTest(component=component), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); media = root/'media'; media.mkdir()
                result = stage(self.fixture(root, component),media,component)
                self.assertEqual(result['package_name'],COMPONENTS[component][0])
                self.assertTrue((media/(component+'.pkg.tar.zst')).is_file())

    def test_monitor_requires_complete_activation_and_paired_terminal(self):
        for case in ('missing-monitor-cli', 'missing-monitor-systemd', 'missing-monitor-bus', 'wrong-monitor-api', 'unpaired-monitor'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);media=root/'media';media.mkdir()
                with self.assertRaises(ValueError): stage(self.fixture(root, 'dev-monitor', case), media, 'dev-monitor')
                self.assertEqual(list(media.iterdir()), [])

    def test_native_replacements_declare_and_carry_complete_relations(self):
        component = 'xdg-desktop-portal-hyprland'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);media=root/'media';media.mkdir()
            result=stage(self.fixture(root, component, version='1.3.12.r1'), media, component)
            self.assertEqual(result['replaces'], 'xdg-desktop-portal-hyprland')
            self.assertEqual(result['version'], '1.3.12.r1')
        for case in ('no-provides', 'no-conflict', 'no-replaces', 'undeclared-replacement', 'missing-portal-file'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);media=root/'media';media.mkdir()
                with self.assertRaises(ValueError): stage(self.fixture(root, component, case), media, component)
                self.assertEqual(list(media.iterdir()), [])
        for case in ('no-console-relations', 'missing-console', 'no-conflict'):
            with self.subTest(component='greetd', case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); media=root/'media'; media.mkdir()
                with self.assertRaises(ValueError): stage(self.fixture(root, 'greetd', case), media, 'greetd')
                self.assertEqual(list(media.iterdir()), [])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);media=root/'media';media.mkdir()
            with self.assertRaises(ValueError): stage(self.fixture(root, 'store', 'foreign-replacement'), media, 'store')
            self.assertEqual(list(media.iterdir()), [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); media = root / 'media'; media.mkdir()
            result = stage(self.fixture(root, 'keyring', version='0.7.1'), media, 'keyring')
            self.assertEqual(result['package_name'], 'enzimos-keyring')
            self.assertEqual(result['replaces'], 'gnome-keyring')
        for case in ('missing-keyring-pam', 'missing-keyring-helper', 'no-conflict'):
            with self.subTest(component='keyring', case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); media = root / 'media'; media.mkdir()
                with self.assertRaises(ValueError): stage(self.fixture(root, 'keyring', case), media, 'keyring')
                self.assertEqual(list(media.iterdir()), [])

    def test_explicit_version_is_bound_to_actual_package_metadata(self):
        for reported in ('0.2.1', '0.2.2', '0.2.1\npkgrel=9', None):
            with self.subTest(reported=reported), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);media=root/'media';media.mkdir()
                path=self.fixture(root, 'dev-monitor', version='0.2.1')
                report=json.loads(path.read_text());report['version']=reported;path.write_text(json.dumps(report))
                if reported == '0.2.1':
                    result=stage(path,media,'dev-monitor');self.assertEqual(result['version'],'0.2.1')
                else:
                    with self.assertRaises(ValueError):stage(path,media,'dev-monitor')
                    self.assertEqual(list(media.iterdir()),[])

    def test_malformed_package_never_creates_media(self):
        for case in ('tamper','identity','duplicate','link','traversal','extra','missing','owner','mode','authorized'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); media=root/'media';media.mkdir()
                with self.assertRaises(ValueError): stage(self.fixture(root,case=case),media,'store')
                self.assertEqual(list(media.iterdir()),[])

    # A package enables its own timer with a relative link and nothing else.
    # A package enables only its own timer, or its own user service with the
    # enzUI session, through a relative link; never another unit or target.
    # Sabotage: return True from enabling_link.
    def test_a_package_may_enable_only_its_own_timer(self):
        for case, allowed in (('timer-link', True), ('session-link', True), ('system-service-link', True),
                              ('foreign-link', False), ('default-target-link', False)):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); media=root/'media';media.mkdir()
                if allowed:
                    self.assertEqual(stage(self.fixture(root,case=case),media,'store')['package_name'],'enzimos-store')
                else:
                    with self.assertRaises(ValueError): stage(self.fixture(root,case=case),media,'store')
                    self.assertEqual(list(media.iterdir()),[])

    # The icon theme is data: theme aliases are relative links to drawings it carries,
    # and nothing in it is executable.
    # Sabotage: return True from theme_link.
    def test_icon_theme_is_data_with_aliases_inside_the_theme(self):
        for case, allowed in (('theme-link', True), ('theme-dir-link', True), ('theme-escape-link', False),
                              ('theme-missing-link', False), ('theme-executable', False), ('timer-link', False)):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); media=root/'media';media.mkdir()
                if allowed:
                    self.assertEqual(stage(self.fixture(root,'icon-theme',case),media,'icon-theme')['package_name'],'enzimos-icon-theme')
                else:
                    with self.assertRaises(ValueError): stage(self.fixture(root,'icon-theme',case),media,'icon-theme')
                    self.assertEqual(list(media.iterdir()),[])

    def test_only_registered_component_configuration_can_enter_etc(self):
        for component, case, allowed in (('developer-tools','configuration',True),
                ('store','configuration',False), ('greetd','wrong-configuration',False), ('developer-tools','wrong-configuration',False),
                ('developer-tools','executable-configuration',False)):
            with self.subTest(component=component,case=case), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);media=root/'media';media.mkdir()
                report=self.fixture(root,component,case)
                if allowed:stage(report,media,component)
                else:
                    with self.assertRaises(ValueError):stage(report,media,component)
                    self.assertEqual(list(media.iterdir()),[])

    def test_terminal_overlay_preserves_base_and_replaces_old_binary(self):
        from terminal_payload import overlay
        for escape in (False, True):
            with self.subTest(escape=escape), tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
                root = Path(directory)
                report = self.fixture(root, 'terminal')
                data = json.loads(report.read_text()); data['revision'] = 'a' * 40
                report.write_text(json.dumps(data))
                desktop = root/'desktop'
                (desktop/'usr/share/enzui').mkdir(parents=True)
                (desktop/'usr/share/enzui/manifest.json').write_text('producer provenance')
                (desktop/'usr/lib').mkdir()
                if escape:
                    outside = root/'outside'; outside.mkdir()
                    (desktop/'usr/lib/enzui').symlink_to(outside, target_is_directory=True)
                    with self.assertRaisesRegex(ValueError, 'escapes desktop'):
                        overlay(report, desktop, root/'result')
                    self.assertEqual(list(outside.iterdir()), [])
                else:
                    binary = desktop/'usr/lib/enzui/apps/terminal-emulator'
                    binary.parent.mkdir(parents=True); binary.write_bytes(b'old Terminal')
                    result = overlay(report, desktop, root/'result')
                    self.assertEqual(binary.read_bytes(), b'old Terminal')
                    self.assertEqual((result/binary.relative_to(desktop)).read_bytes(), b'fixture native executable')
                    self.assertEqual((result/'usr/share/enzui/manifest.json').read_text(), 'producer provenance')
                    binding = json.loads((result/'usr/share/enzui/terminal-ownership.json').read_text())
                    self.assertEqual(binding['revision'], 'a' * 40)


class ReplacedArchPackage(unittest.TestCase):
    def test_target_cohort_must_not_depend_on_a_replaced_package(self):
        from build_install_iso import Invalid, replaced_dependents
        with tempfile.TemporaryDirectory() as directory:
            cohort = Path(directory); (cohort/'packages').mkdir(); records = []
            for name, depends in (('grim', ['wayland']), ('portal-user', ['xdg-desktop-portal-hyprland>=1.4'])):
                info = f'pkgname = {name}\npkgver = 1-1\n' + ''.join(f'depend = {d}\n' for d in depends)
                path = cohort/'packages'/f'{name}-1-1-x86_64.pkg.tar.zst'
                with tarfile.open(path, 'w:zst') as archive:
                    member = tarfile.TarInfo('.PKGINFO'); member.size = len(info)
                    archive.addfile(member, io.BytesIO(info.encode()))
                records.append({'name': name, 'url': 'https://example.invalid/'+path.name})
            replaced_dependents(cohort, records[:1], {'xdg-desktop-portal-hyprland'})
            with self.assertRaisesRegex(Invalid, 'portal-user depends on replaced'):
                replaced_dependents(cohort, records, {'xdg-desktop-portal-hyprland'})
