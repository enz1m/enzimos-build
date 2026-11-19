# SPDX-License-Identifier: MIT
"""Actual native Terminal client; no approval or input acknowledgements invented."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

LAB = Path('/var/tmp/enzimos-gaming-lab')
DATA = LAB / 'fixtures'
mode = sys.argv[1]
flatpak_display = sys.argv[2] if len(sys.argv) == 3 else None
assert flatpak_display in (None, 'x11') and (flatpak_display is None or mode == 'flatpak')
assert os.getuid() == 1000 and mode in ('native', 'flatpak', 'proton', 'load', 'steam-native', 'steam-flatpak')
result = {'flatpak_display_requested': flatpak_display, 'mode': mode, 'uid': os.getuid(), 'session_id': os.environ.get('XDG_SESSION_ID'), 'checks': []}
children = []


def run(argv, timeout=90, env=None):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    print(p.stdout[-12000:] + p.stderr[-3000:], flush=True)
    result['checks'].append({'command': Path(argv[0]).name, 'returncode': p.returncode, 'stdout': p.stdout[-12000:], 'stderr': p.stderr[-3000:]})
    assert p.returncode == 0, (Path(argv[0]).name, p.returncode)
    return p.stdout


try:
    environment = dict(os.environ, SDL_AUDIODRIVER='pulseaudio', SDL_VIDEODRIVER='wayland')
    if not mode.startswith('steam-'):
        if 'enzimosfixture' not in run(['pactl', 'list', 'short', 'sinks']):
            run(['pactl', 'load-module', 'module-null-sink', 'sink_name=enzimosfixture'])
        run(['pactl', 'set-default-sink', 'enzimosfixture'])
    if mode.startswith('steam-'):
        # Explicit online first-launch acceptance. An actual rendered sign-in
        # window must be reviewed before the normal user writes the marker.
        review = LAB / 'clients' / (mode + '-reviewed')
        assert not review.exists()
        log = LAB / 'clients' / (mode + '-bootstrap.log')
        stream = log.open('w')
        command = ['steam'] if mode == 'steam-native' else ['flatpak', 'run', 'com.valvesoftware.Steam']
        launch = subprocess.Popen(command, stdout=stream, stderr=stream)
        children.append(launch)
        print('ENZIMOS_STEAM_BOOTSTRAP_REVIEW_REQUIRED ' + str(review), flush=True)
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            assert launch.poll() is None, ('Steam bootstrap exited', launch.returncode)
            if review.is_file():
                assert review.stat().st_uid == os.getuid() and review.stat().st_size == 0
                break
            time.sleep(.3)
        else: raise AssertionError('actual Steam sign-in window review deadline')
        result['bootstrap'] = {'path': mode, 'launcher_alive': launch.poll() is None,
                               'actual_sign_in_window_review_marker': str(review),
                               'no_account_login_or_commercial_game': True}
    elif mode == 'proton':
        # Direct maintained Proton Wine components in the Steam runtime. No
        # proprietary Windows DLLs or global compatibility tool replacement.
        tool = DATA / 'GE-Proton11-7-x86_64/files/bin/wine'
        prefix = LAB / 'clients/proton-prefix'
        prefix.mkdir(mode=0o700, exist_ok=True)
        text = run(['flatpak', 'run', '--filesystem=' + str(LAB),
                    '--env=WINEPREFIX=' + str(prefix), '--env=WINEDEBUG=-all',
                    '--command=' + str(tool), 'com.valvesoftware.Steam', str(DATA / 'mfprobe.exe')], timeout=240)
        assert 'ENZIMOS_PROTON_MF_H264_RAW_VIDEO_PASS' in text and 'ENZIMOS_PROTON_MF_AAC_RAW_AUDIO_PASS' in text
    else:
        if mode in ('native', 'load'):
            text = run([str(DATA / 'abi32')])
            assert 'ENZIMOS_GAMING_32BIT_ABI_AND_GAMEMODE_PASS' in text
            command = ['gamemoderun', str(DATA / 'gameprobe')]
        else:
            base = ['flatpak', 'run', '--filesystem=' + str(DATA) + ':ro']
            text = run(base + ['--command=' + str(DATA / 'abi32'), 'com.valvesoftware.Steam'])
            assert 'ENZIMOS_GAMING_32BIT_ABI_AND_GAMEMODE_PASS' in text
            # pressure-vessel uses Flatpak's portal to create a sibling
            # subsandbox. Direct nested userns creation is normally forbidden.
            run(base + ['--command=flatpak-spawn', 'com.valvesoftware.Steam',
                        '--sandbox', '--no-network', '/usr/bin/true'])
            display_options = ['--env=SDL_VIDEODRIVER=x11'] if flatpak_display else []
            command = base + display_options + ['--env=SDL_AUDIODRIVER=pulseaudio',
                              '--command=gamemoderun', 'com.valvesoftware.Steam', str(DATA / 'gameprobe')]
        if mode == 'load':
            # Genuine 4096-token inference competes with rendering and a bounded
            # file copy. It uses the existing opt-in calibration supervisor.
            model = DATA / 'model.gguf'
            server = '/usr/lib/enzimos-inference/cpu/llama-server'
            private = LAB / 'clients'
            config = private / 'inference.json'
            registry = {'schema': 1, 'context': 4608, 'cpu_threads': 1, 'backend': 'cpu', 'memory_mib': 1900,
                        'default_model': 'fixture', 'models': {'fixture': {'path': str(model), 'sha256': hashlib.sha256(model.read_bytes()).hexdigest()}},
                        'runtimes': {'cpu': {'server': server, 'revision': 'installed-fixture', 'artifact_sha256': hashlib.sha256(Path(server).read_bytes()).hexdigest()}}}
            config.write_text(json.dumps(registry)); config.chmod(0o600)
            log = (private / 'inference.log').open('w')
            inference = subprocess.Popen(['systemd-run', '--user', '--unit=enzimos-gaming-inference', '--slice=background.slice', '--wait', '--pipe',
                '--property=MemoryMax=2G', '--property=MemorySwapMax=0', '--property=TasksMax=64', '--property=CPUQuota=100%', '--property=Nice=15',
                'enzimos-inference-calibrate', '--config', str(config), '--model', 'fixture', '--receipt', str(private / 'inference-receipt.json'), '--run', '--managed'], stdout=log, stderr=log)
            children.append(inference)
            time.sleep(20)
            assert inference.poll() is None
            children.append(subprocess.Popen(['systemd-run', '--user', '--unit=enzimos-gaming-copy', '--slice=background.slice', '--wait', '--pipe',
                '--property=Nice=15', '--property=IOSchedulingClass=idle', 'dd', 'if=' + str(model), 'of=' + str(private / 'copy.gguf'), 'bs=1M', 'conv=fsync'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        text = run(command, env=environment)
        assert 'ENZIMOS_GAMEPROBE' in text and 'audio_driver=pulseaudio' in text
        if mode == 'load':
            assert children[0].wait(timeout=1500) == 0, (private / 'inference.log').read_text()[-6000:]
            receipt = json.loads((private / 'inference-receipt.json').read_text())
            result['calibration'] = receipt
            assert children[1].wait(timeout=30) == 0
            assert hashlib.sha256((private / 'copy.gguf').read_bytes()).hexdigest() == registry['models']['fixture']['sha256']
            run(['systemctl', '--user', 'show', 'background.slice', '-p', 'CPUWeight', '-p', 'IOWeight'])
    result['status'] = 'PASS'
except BaseException as error:
    result['status'] = 'FAIL'; result['failure'] = type(error).__name__ + ': ' + str(error)[:4000]
finally:
    if mode == 'steam-native':
        subprocess.run(['steam', '-shutdown'], capture_output=True, timeout=30)
    elif mode == 'steam-flatpak':
        subprocess.run(['flatpak', 'kill', 'com.valvesoftware.Steam'], capture_output=True, timeout=30)
    if mode == 'load':
        # Stop the actual owned units, not just the systemd-run client process.
        subprocess.run(['systemctl', '--user', 'stop', 'enzimos-gaming-inference.service', 'enzimos-gaming-copy.service'],
                       capture_output=True, timeout=20)
    for child in children:
        if child.poll() is None: child.terminate()
    output = LAB / 'clients' / (mode + '.json')
    output.write_text(json.dumps(result)); print('ENZIMOS_GAMING_CLIENT_DONE ' + mode + ' ' + result['status'], flush=True)
