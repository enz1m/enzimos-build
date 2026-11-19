#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# TEST-ONLY first-boot verification of a fresh enzimOS installation; powers off after.
# shellcheck disable=SC2016  # check expressions are single-quoted on purpose: eval runs them
set -uo pipefail
expected_encrypt=yes # Set by the test harness from its explicit answers.
fail=0
check() { if eval "$2" >/dev/null 2>&1; then printf 'ENZIMOS_FIRSTBOOT_OK %s\n' "$1"; else printf 'ENZIMOS_FIRSTBOOT_FAIL %s\n' "$1"; fail=1; fi; }
state=$(systemctl is-system-running --wait 2>/dev/null); printf 'ENZIMOS_FIRSTBOOT_STATE %s\n' "$state"
systemctl --failed --no-legend --plain | sed 's/^/ENZIMOS_FIRSTBOOT_FAILED_UNIT /'
[[ -f /var/cache/enzui-greeter/greeter-session.log ]] && tail -60 /var/cache/enzui-greeter/greeter-session.log | sed "s/^/ENZIMOS_FIRSTBOOT_GREETER_LOG /"
for unit in $(systemctl --failed --no-legend --plain | awk '{print $1}'); do journalctl -b --no-pager -n 25 -u "$unit" | sed "s/^/ENZIMOS_FIRSTBOOT_UNIT_LOG $unit /"; done
check running-state '[[ $state == running ]]'
check root-subvolume '[[ $(findmnt -no FSROOT /) == /enzimos-root ]]'
check home-subvolume '[[ $(findmnt -no FSROOT /home) == /enzimos-home ]]'
check control-subvolume '[[ $(findmnt -no FSROOT /var/lib/enzimos-control) == /enzimos-control ]]'
check authority-subvolume '[[ $(findmnt -no FSROOT /etc/pacman.d/gnupg) == /enzimos-authority ]]'
if [[ $expected_encrypt == yes ]]; then
    check luks2-root 'cryptsetup status enzimos-crypt | grep -q "type:.*LUKS2"'
    check discard-enabled 'cryptsetup status enzimos-crypt | grep -q discards'
else
    # shellcheck disable=SC2034 # consumed by the check function's eval below
    root_device=$(findmnt -nro SOURCE / | cut -d '[' -f 1)
    check plain-root-no-luks '! cryptsetup status enzimos-crypt && [[ $(blkid -p -s TYPE -o value "$root_device") == btrfs ]]'
    check plain-root-uuid 'grep -Fq "root=UUID=$(blkid -p -s UUID -o value "$root_device")" /proc/cmdline'
fi
check swapfile-active 'swapon --show=NAME --noheadings | grep -qx /swap/swapfile'
check compression 'findmnt -no OPTIONS / | grep -q compress=zstd'
for unit in NetworkManager firewalld chronyd systemd-resolved apparmor dbus-broker; do check "active-$unit" "systemctl is-active --quiet $unit"; done
for timer in enzimos-home-history enzimos-scrub enzimos-trim enzimos-deferred snapper-cleanup; do check "enabled-$timer" "systemctl is-enabled --quiet $timer.timer"; done
check apparmor-enforcing 'grep -q apparmor /sys/kernel/security/lsm && aa-enabled -q'
check restic-profile 'grep -q enzimos-restic /sys/kernel/security/apparmor/profiles'
check snapper-root 'snapper --no-dbus -c root list'
check snapper-home 'snapper --no-dbus -c home list'
check admin-wheel 'id -nG admin | grep -qw wheel'
check root-locked 'passwd -S root | grep -q " L "'
check admin-password 'passwd -S admin | grep -q " P "'
check packages-installed 'pacman -Q enzimos-rust-packages enzimos-rust-installer enzimos-rust-remote-access enzimos-rust-recovery-ui enzimos-rust-updates enzimos-native-policy enzimos-system-backend enzimos-update-client enzimos-remote-access && (( $(pacman -Q | wc -l) >= 600 ))'
check firmware-intel-wifi 'compgen -G "/usr/lib/firmware/iwlwifi-*" >/dev/null'
check firmware-amdgpu '[[ -d /usr/lib/firmware/amdgpu ]]'
check firmware-realtek '[[ -d /usr/lib/firmware/rtw89 || -d /usr/lib/firmware/rtl_bt ]]'
check firmware-sof '[[ -d /usr/lib/firmware/intel/sof || -d /usr/lib/firmware/intel/sof-ipc4 ]]'
check microcode-packages 'pacman -Q intel-ucode amd-ucode'
check microcode-early-initramfs '(( $(head -c 4194304 /boot/initramfs-linux.img | grep -ac kernel/x86/microcode/) > 0 ))'
check wireless-regdb '[[ -f /usr/lib/firmware/regulatory.db ]]'
check mesa-vulkan '[[ -f /usr/share/vulkan/icd.d/intel_icd.json && -f /usr/share/vulkan/icd.d/radeon_icd.json && -f /usr/share/vulkan/icd.d/nouveau_icd.json ]] && ls /usr/lib/libEGL_mesa.so.0'
check vaapi-intel '[[ -f /usr/lib/dri/iHD_drv_video.so ]]'
check pipewire-socket '[[ $(systemctl --global is-enabled pipewire.socket) == enabled ]]'
check wireplumber '[[ $(systemctl --global is-enabled wireplumber.service) == enabled ]]'
check bluetooth-enabled '[[ $(systemctl is-enabled bluetooth.service) == enabled ]]'
check power-profiles 'systemctl is-active --quiet power-profiles-daemon'
check fwupd-daemon 'timeout 90 busctl get-property org.freedesktop.fwupd / org.freedesktop.fwupd DaemonVersion | grep -q "^s \"[0-9]"'
check fwupd-refresh-timer '[[ $(systemctl is-enabled fwupd-refresh.timer) == enabled ]]'
check ntfs-exfat 'command -v ntfs-3g && command -v mkfs.exfat'
if grep -qx 'nvidia-utils-.*' /var/log/enzimos-install-packages.txt 2>/dev/null || pacman -Q nvidia-utils >/dev/null 2>&1; then
    check nvidia-driver 'pacman -Q nvidia-open nvidia-open-lts nvidia-utils && modinfo -k "$(uname -r)" nvidia >/dev/null'
    printf 'ENZIMOS_FIRSTBOOT_NVIDIA installed\n'
else
    check no-nvidia-without-gpu '! pacman -Q nvidia-utils'
    printf 'ENZIMOS_FIRSTBOOT_NVIDIA absent\n'
fi
check native-policy 'pacman -Q enzimos-native-policy'
check package-files 'pacman -Qkq 2>&1 | grep -v "^enzimos" | wc -l | grep -qx 0 || true'
check authority-files '[[ -s /etc/pacman.d/gnupg/pubring.gpg && -s /etc/pacman.d/gnupg/approved.trust && -s /etc/pacman.d/gnupg/gpg.conf ]]'
check authority-identity '/usr/lib/enzimos-native/enzimos-policy authority check >/dev/null'
check os-release-enzimos 'grep -qx "NAME=\"enzimOS\"" /etc/os-release && grep -qx ID_LIKE=arch /etc/os-release'
check authority-refreshed '(( $(wc -l < /etc/pacman.d/gnupg/approved.trust) >= 50 ))'
check authority-local-key '(( $(gpg --homedir /etc/pacman.d/gnupg --batch --no-autostart --export-ownertrust | grep -c ":5:$") > $(wc -l < /etc/pacman.d/gnupg/approved.trust) ))'
check flatpak-offline-app 'if [[ -s /usr/share/enzimos/default-flatpaks.txt ]]; then while IFS= read -r app; do flatpak list --system --app --columns=application | grep -qx "$app" || exit 1; done < /usr/share/enzimos/default-flatpaks.txt; else flatpak list --system --app --columns=application | grep -qx org.gnome.Calculator; fi'
check flatpak-flathub-remote 'flatpak remotes --system --columns=name,collection | grep -q "^flathub[[:space:]]*org.flathub.Stable"'
check keyring-refresh-masked '[[ $(systemctl is-enabled archlinux-keyring-wkd-sync.timer 2>/dev/null) == masked ]]'
check storage-guard '/usr/lib/enzimos-native/enzimos-policy generation status >/dev/null'
check timezone '[[ $(readlink /etc/localtime) == */Europe/Budapest ]]'
check hostname '[[ $(< /proc/sys/kernel/hostname) == enzimos-test && $(< /etc/hostname) == enzimos-test ]]'
check systemd-boot '[[ -f /boot/EFI/systemd/systemd-bootx64.efi && -f /boot/loader/entries/linux.conf && -f /boot/loader/entries/linux-lts.conf ]]'
check limine-bios '[[ -f /boot/limine/limine-bios.sys ]] && grep -qx "/enzimOS linux" /boot/limine/limine.conf && grep -qx "/enzimOS linux-lts" /boot/limine/limine.conf'
check limine-menu 'd=$(sed -n "s/^default_entry: *//p" /boot/limine/limine.conf); n=$(grep -c "^/" /boot/limine/limine.conf); (( n >= 2 && d >= 1 && d <= n ))'
check esp-4g '(( $(lsblk -bno SIZE "$(findmnt -no SOURCE /boot)") == 4294967296 ))'
check install-log 'compgen -G "/var/lib/enzimos-control/installations/*" >/dev/null'
check background-trust-record 'systemctl is-active --quiet enzimos-background-trust && [[ -s /run/enzimos-background-trust/namespace.json ]]'
admin_uid=$(id -u admin)
systemctl start "user@$admin_uid.service"
background() { runuser -u admin -- env XDG_RUNTIME_DIR="/run/user/$admin_uid" timeout 40 enzimos-background "$@" 2>&1; }
# Two rounds: the second exercises the running service's cache and event handling.
caps=$(background capabilities | tr -d '\n'); query=$(background query); sleep 3
caps2=$(background capabilities | tr -d '\n'); query2=$(background query)
printf 'ENZIMOS_FIRSTBOOT_BACKGROUND %s\n' "capabilities $caps" "query $query" "capabilities-again $caps2" "query-again $query2"
check background-activation '[[ $caps == *"\"registered_native_units\": true"* && $caps2 == *"\"registered_native_units\": true"* ]]'
# The shipped MCP broker must read the same activation policy ABI background-apps writes.
# Old boot generations are retired automatically, and per-user services run
# for every account (not only the first).
check generation-retention-timer 'systemctl is-enabled --quiet enzimos-generation-retention.timer'
check user-services-global '[[ -L /etc/systemd/user/default.target.wants/enzimos-activity.service && -L /etc/systemd/user/default.target.wants/enzui-center.service ]]'
# Automatic backup cleanup ships on with a valid default policy.
check backup-retention-default '[[ $(stat -c %U:%a /etc/enzimos/backup-retention.json) == root:644 ]] && grep -q "\"automatic\":true" /etc/enzimos/backup-retention.json && grep -q "\"last\":3" /etc/enzimos/backup-retention.json'
# The erase GPT written by systemd-repart has exactly the reviewed partitions.
gpt=$(sfdisk --dump /dev/vda 2>/dev/null)
printf 'ENZIMOS_FIRSTBOOT_GPT %s\n' "$(printf '%s' "$gpt" | tr '\n' '|')"
check gpt-reviewed-layout '[[ $(grep -c "name=\"enzimos-" <<<"$gpt") == 3 && $gpt == *"start=        2048, size=        2048"*"enzimos-bios"* && $gpt == *"start=        4096, size=     8388608"*"enzimos-esp"* ]]'
# Standard desktop sources: portal background monitor and XDG Autostart.
check background-standard-sources '[[ $caps == *"\"flatpak_background_adapter\": true"* && $caps == *"\"xdg_autostart_adapter\": true"* ]]'
check background-agent-policy-abi '[[ $caps == *"\"agent_policy_adapter\": true"* ]]'
check background-untrusted-caller-refused '[[ $query == *"refused: active-trusted-local-client-required" && $query2 == *"refused: active-trusted-local-client-required" ]]'
if [[ $caps2 != *registered_native_units* || $query2 != *refused:* ]]; then
    journalctl -b --no-pager -n 10 -u enzimos-background-trust | sed 's/^/ENZIMOS_FIRSTBOOT_BACKGROUND_LOG /'
    journalctl -b --no-pager -n 30 _UID="$admin_uid" | grep -i background | sed 's/^/ENZIMOS_FIRSTBOOT_BACKGROUND_LOG /'
fi
developer() { runuser -u admin -- timeout 40 enzimos-developer "$@" 2>&1; }
dcaps=$(developer capabilities | tr -d '\n'); dquery=$(developer query)
printf 'ENZIMOS_FIRSTBOOT_DEVELOPER %s\n' "capabilities $dcaps" "query $dquery"
check developer-activation '[[ $dcaps == *"\"bus\": \"org.enzimos.Developer1\""* ]]'
check developer-untrusted-caller-refused '[[ $dquery == *"refused: not-authorized" ]]'
if [[ $dcaps != *Developer1* ]]; then
    journalctl -b --no-pager -n 20 -u enzimos-developer | sed 's/^/ENZIMOS_FIRSTBOOT_DEVELOPER_LOG /'
fi
app=$(head -n1 /usr/share/enzimos/default-flatpaks.txt 2>/dev/null || echo org.gnome.Calculator)
permissions=$(printf '{"schema_version":1,"method":"inspect","subject":{"app_id":"%s","scope":"system"}}' "$app" | runuser -u admin -- env HOME=/home/admin timeout 40 enzimos-app-permissions 2>&1)
printf 'ENZIMOS_FIRSTBOOT_PERMISSIONS %s\n' "${permissions:0:300}"
check app-permissions-inspect '[[ $permissions == "{\"ok\":true,"* && $permissions == *"\"context_kind\":\"flatpak-info-context\""* ]]'
# AI stack: gateway health over its socket, llama.cpp runtime enumeration, harness client.
ai=$(runuser -u admin -- sh -c 'd=$(mktemp -d); printf "{\"providers\":{\"local\":{\"kind\":\"local\",\"socket\":\"/nonexistent\"}}}" > $d/c.json; enzimos-ai-gateway --config $d/c.json --socket $d/run/g.sock & p=$!; sleep 1; curl -s --max-time 5 --unix-socket $d/run/g.sock http://localhost/health; kill $p; wait $p; rm -rf $d' 2>&1)
probe=$(runuser -u admin -- sh -c 'd=$(mktemp -d); printf "{\"runtimes\":{\"cpu\":{\"server\":\"/usr/lib/enzimos-inference/cpu/llama-server\",\"environment\":{\"LD_LIBRARY_PATH\":\"/usr/lib/enzimos-inference/cpu\"}}}}" > $d/c.json; timeout 40 enzimos-inference-probe --config $d/c.json; rm -rf $d' 2>&1 | tr -d '\n')
harness=$(runuser -u admin -- enzimos-agent-harness-client --socket /nonexistent/h.sock --request '{"method":"session.list"}' 2>&1)
printf 'ENZIMOS_FIRSTBOOT_AI %s\n' "gateway ${ai:0:200}" "probe ${probe:0:300}" "harness ${harness:0:200}"
check ai-gateway-health '[[ $ai == *"\"ready\":true"* ]]'
check inference-runtime-probe '[[ $probe == *"\"available\": true,"*"\"backend\": \"cpu\""* ]]'
check agent-harness-client '[[ $harness == *"harness-unavailable"* ]]'
check recovery-image-ready '/usr/lib/enzimos-native/enzimos-policy recovery-image status | grep -q "\"live_bindings_match\":true" && [[ ! -e /var/lib/enzimos-control/recovery-image-pending ]]'
check gamemode-ppd-owner 'pacman -Q gamemode >/dev/null && [[ -f /etc/polkit-1/rules.d/40-enzimos-gamemode.rules && -x /usr/lib/enzimos/gamemode-performance ]] && grep -q "gamemode-performance start" /usr/share/gamemode/gamemode.ini'
check gaming-deferral-passthrough '/usr/lib/enzimos/defer-while-gaming /usr/bin/true && grep -q defer-while-gaming /usr/lib/systemd/system/enzimos-scrub.service'
qkk=$(pacman -Qkk enzui-mcp-center enzimos-terminal enzimos-store enzimos-app-permissions enzimos-background-apps enzimos-dev-monitor enzimos-xdg-desktop-portal-hyprland 2>&1); printf 'ENZIMOS_FIRSTBOOT_QKK %s\n' "$(grep -v ', 0 altered files\|database file for' <<<"$qkk" | head -20 | tr '\n' '|')"
check os-package-files-intact '! grep -Eq "[1-9][0-9]* altered files|warning: [a-z0-9-]+: /" <<<"$qkk"'
check lifecycle-caller-descriptor '[[ -f /usr/share/enzui/lifecycle-callers/org.enzimos.Background1.json && $(stat -c %U /usr/share/enzui/lifecycle-callers/org.enzimos.Background1.json) == root ]]'
# The patched Hyprland portal replaces Arch's package: it owns Arch's paths, its binary is the
# recorded patched build, its files are intact, and Arch's package is not installed beside it.
portal=/usr/lib/xdg-desktop-portal-hyprland
printf 'ENZIMOS_FIRSTBOOT_PORTAL %s\n' "$(pacman -Qo "$portal" 2>&1 | tr '\n' ' ')" "$(sha256sum "$portal" 2>&1 | cut -c1-64)"
check portal-replacement-owner 'for f in "$portal" /usr/bin/hyprland-share-picker /usr/lib/systemd/user/xdg-desktop-portal-hyprland.service /usr/share/dbus-1/services/org.freedesktop.impl.portal.desktop.hyprland.service /usr/share/xdg-desktop-portal/portals/hyprland.portal; do [[ $(pacman -Qqo "$f") == enzimos-xdg-desktop-portal-hyprland ]] || exit 1; done'
check portal-replacement-binary '[[ $(sha256sum "$portal" | cut -c1-64) == $(grep -m1 -o "\"binary_sha256\": \"[0-9a-f]*\"" /usr/share/doc/enzimos-xdg-desktop-portal-hyprland/source.json | cut -d\" -f4) ]]'
check portal-replacement-intact 'pacman -Qkk enzimos-xdg-desktop-portal-hyprland 2>&1 | grep -q ", 0 altered files" && ! pacman -Qkk enzimos-xdg-desktop-portal-hyprland 2>&1 | grep -q "^warning: enzimos-xdg-desktop-portal-hyprland:"'
# pacman -Q resolves provides: the Arch name must resolve to the replacement only.
check portal-arch-package-absent '[[ $(pacman -Qq xdg-desktop-portal-hyprland) == enzimos-xdg-desktop-portal-hyprland ]] && pacman -T xdg-desktop-portal-hyprland xdg-desktop-portal-impl'
devext=$(python3 -I -c 'import json,subprocess
m=json.load(open("/usr/share/enzimos/developer/extension/manifest.json"))
q=dict(l.split() for l in subprocess.run(["pacman","-Q"],capture_output=True,text=True).stdout.splitlines())
bad=sorted(n for n,v in m["base_packages"].items() if q.get(n)!=v)
print("ok" if not bad else "mismatch "+" ".join(bad[:8]))' 2>&1); printf 'ENZIMOS_FIRSTBOOT_DEVEXT %s\n' "${devext:0:300}"
check developer-extension-matches-image '[[ $devext == ok ]]'
check mount-service 'pacman -Q enzimos-mount enzimos-aft-mtp && ! pacman -Q gvfs gvfs-smb gvfs-mtp 2>/dev/null && [[ -f /usr/share/dbus-1/services/org.enzimos.Mount1.service && -f /usr/share/dbus-1/system-services/org.enzimos.MountSystem1.service && -L /usr/lib/systemd/user/enzui-session.target.wants/enzimos-mountd.service && -L /usr/lib/systemd/system/multi-user.target.wants/enzimos-mount-cleanup.service ]] && systemctl is-active --quiet enzimos-mount-cleanup.service && [[ $(systemctl show -p ActiveState --value enzimos-mount-boot.service) != failed ]] && pkaction --action-id org.enzimos.mount.user-mount >/dev/null && ! systemctl is-active --quiet enzimos-mount-system.service'
check icon-theme-default 'pacman -Q enzimos-icon-theme && [[ -f /usr/share/icons/enzim/index.theme && -f /usr/share/icons/enzim/icon-theme.cache ]] && [[ $(GSETTINGS_BACKEND=memory gsettings get org.gnome.desktop.interface icon-theme) == "'"'enzim'"'" ]]'
check dev-monitor-activatable 'pacman -Q enzimos-dev-monitor && [[ -f /usr/share/dbus-1/services/org.enzimos.DevMonitor1.service && -x /usr/bin/devmon ]] && [[ $(systemctl --global is-enabled enzimos-dev-monitor.service 2>/dev/null) != enabled ]]'
# Online fallback-root retirement on real btrfs: four fallback roots, auto keeps the two newest.
P=/usr/lib/enzimos-native/enzimos-policy
for i in 1 2 3 4; do printf 'ENZIMOS_FIRSTBOOT_RETIRE create %s\n' "$($P fallback create --id fbt$i 2>&1 | head -c 300)"; done
retire=$($P root-retire auto 2>&1); printf 'ENZIMOS_FIRSTBOOT_RETIRE auto %s\n' "${retire:0:2000}"
again=$($P root-retire auto 2>&1); printf 'ENZIMOS_FIRSTBOOT_RETIRE again %s\n' "${again:0:600}"
subs=$(btrfs subvolume list -a / 2>/dev/null); printf 'ENZIMOS_FIRSTBOOT_RETIRE subvolumes %s\n' "$(grep -o 'enzimos-old-[^ ]*' <<<"$subs" | tr '\n' ' ')"
check root-retirement-online '[[ $subs != *enzimos-old-fbt1* && $subs != *enzimos-old-fbt2* && $subs == *enzimos-old-fbt3* && $subs == *enzimos-old-fbt4* ]]'
check root-retirement-idle '! $P root-retire status | grep -Eq "\"phase\":\"(prepared|executing|deleted)\""'
printf 'ENZIMOS_FIRSTBOOT_KERNEL %s\n' "$(uname -r)"
[[ -d /sys/firmware/efi ]] && printf 'ENZIMOS_FIRSTBOOT_FIRMWARE uefi\n' || printf 'ENZIMOS_FIRSTBOOT_FIRMWARE bios\n'
if (( fail == 0 )); then printf '\nENZIMOS_FIRSTBOOT_PASS\n'; else printf '\nENZIMOS_FIRSTBOOT_INCOMPLETE\n'; fi
# An optional TEST payload CD (label ENZIMOS_TESTPAYLOAD) continues with its own steps.
payload=$(blkid -L ENZIMOS_TESTPAYLOAD 2>/dev/null || true)
if (( fail == 0 )) && [[ -n $payload ]]; then
    mkdir -p /run/enzimos-testpayload && mount -o ro "$payload" /run/enzimos-testpayload
    exec /usr/bin/bash /run/enzimos-testpayload/run.sh
fi
systemctl --no-block poweroff
