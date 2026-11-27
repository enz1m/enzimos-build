# enzimOS Build Tools

Tools for checking enzimOS manifests, preparing package inputs, assembling
development installation media and running integration checks in disposable VMs.

## Build the installation ISO

`build_iso.py` builds the full enzimOS installation ISO from published
packages. It needs an x86_64 Linux system with root access, Python 3.11 or
newer, `gpg`, `tar`, `zstd` and about 60 GB of free disk space.

```sh
git clone https://github.com/enz1m/enzimos-build
cd enzimos-build
sudo python3 build_iso.py --output ~/enzimos-iso
```

The output directory receives the ISO (`enzimos-YYYYMMDD-x86_64.iso`, about
9.5 GB), its SHA-256 checksum, a JSON summary of the package versions and the
assembler's `build.json`. Each build uses the newest published packages:

- Arch Linux packages from the Arch mirrors, checked against the Arch Linux
  master keys;
- enzimOS packages from the `enzimos` and `enzimos-os` repositories at
  [packages.enzim.dev](https://packages.enzim.dev), checked against the pinned
  enzimOS repository key;
- the default Flatpak apps from [flatpak.enzim.dev](https://flatpak.enzim.dev)
  and their Flathub runtimes.

This repository pins only the package names (`build_iso.py` and
`headless_plan.py`). The builder prepares an Arch build root from the
signature-checked Arch bootstrap image, so any distribution can host the
build. Root access is used only for that build root; the packages are verified
and the ISO is assembled by an unprivileged user inside it, so the host kernel
must allow unprivileged user namespaces.

A first build downloads about 7 GB and uses about 32 GB in the work directory
(`--work`, default `OUTPUT/work`). Later builds reuse the downloads. Use
`--fast` for quicker compression while testing and `--no-flatpak` to leave out
the offline apps. Supply `--secure-key` and `--secure-certificate` to sign the
boot files for firmware that trusts your own Secure Boot key.

The signed `enzimos-iso-desktop` stage carries the Shell build's private
Xwayland companion to both the live and installed desktops. For stages with
an Xwayland pin, the assembler checks its executable, license and runtime
packages against the desktop build's receipt and the Arch package cohort.
The media manifest records the admitted Xwayland build.

### Check the image in a VM

Install the image unattended in a local QEMU/KVM VM from this checkout:

```sh
python3 -c "import install_iso_vm as v; print(v.run('install', 'uefi', '/tmp/enzimos-vm',
    iso='$HOME/enzimos-iso/enzimos-YYYYMMDD-x86_64.iso', guest_ram_mib=4096))"
```

The installer stages the native packages in RAM, so the VM needs 4 GiB and
the host about 8 GiB of free memory.

### Add your own files

The desktop stage is the file tree copied onto the live and installed
systems. After a first build, copy the published stage from
`OUTPUT/work/build/desktop`, change the copy and build again with it:

```sh
sudo cp -a ~/enzimos-iso/work/build/desktop ~/my-desktop
# add or change files under ~/my-desktop (as root: the stage keeps root-only files)
sudo python3 build_iso.py --output ~/enzimos-iso --desktop ~/my-desktop
```

For example, to add Surface Laptop touch and pen support:

1. Apply the `drivers/hid/ipts/` hunks from the [Linux Surface IPTS patch](https://github.com/linux-surface/linux-surface/blob/arch-7.2.15-1/patches/7.2/0005-ipts.patch).
   Build the module against the headers of the kernel the ISO carries (the
   `kernel` field of the JSON summary) with
   `make -C "$KERNEL_HEADERS" M="$IPTS_DRIVER" CONFIG_HID_IPTS=m modules`.
2. Build [iptsd v3.1.1](https://github.com/linux-surface/iptsd/tree/v3.1.1) with
   Meson, prefix `/usr`, systemd support and `-Ddebug_tools=[]`, and install it
   to a temporary `DESTDIR`.
3. Add both to the stage copy:

   ```sh
   sudo python3 stage_surface_touch.py ~/my-desktop \
       --module "$IPTS_DRIVER/ipts.ko" \
       --iptsd-stage "$IPTSD_STAGE" \
       --kernel-release "$KERNEL_RELEASE"
   ```

The module loads only on the exact kernel it was built for, so rebuild it when
the published kernel changes. DMA remapping and module signature enforcement
can require a separately qualified kernel.

## Refresh a cached Arch cohort

For a cached development cohort, `acquire_packages.py` normally fetches every
archive from the plan's dated `repository_snapshot`. A package record can
specify its own `repository_snapshot` to refresh one package without changing
the baseline. Use the replacement's URL, archive size and SHA-256 from its
snapshot metadata. Verify the package signature and resolve dependencies
against the complete resulting cohort.

## Validate the manifests

Clone [enzimOS Manifests](https://github.com/enz1m/enzimos-manifests) alongside
this repository. Pass its path explicitly if you check it out somewhere else.

```sh
python3 cli.py validate --manifests ../enzimos-manifests
python3 cli.py plan --manifests ../enzimos-manifests
```

`validate` checks the distribution policy and app catalogue. `plan` lists
the required artifacts and outstanding release checks.

## Build and test

The manifest CLI requires Python 3.11 or newer. Use Python 3.14 or newer for
the full test suite and Zstandard package audits.

```sh
python3 -m unittest discover -s tests
```

Keep [enzimOS Packages](https://github.com/enz1m/enzimos-packages) and the
[Installer Backend](https://github.com/enz1m/enzimos-installer) beside this
checkout for the policy staging and boot menu tests. The suite runs offline
and uses temporary files and synthetic fixtures.

- `signed_bootstrap.py` and `package_trust.py` verify separately supplied
  bootstrap and package inputs.
- `build_native_policy.py` builds the native policy package in a
  network-disabled sandbox. `build_system_backend.py` builds the matching
  System1 activation package from the Packages checkout.
- `build_install_iso.py` assembles development media from a verified package
  cohort, the desktop stage and reviewed runtime packages. Run it with
  `--help` for the accepted inputs.
- `install_iso_vm.py` checks separately built images using disposable VM disks.

Full image assembly requires reviewed inputs and built packages for Packages,
Installer Backend, Remote Access, Recovery UI and Updates, plus a staged
desktop with the graphical installer. Include `linux-firmware-marvell` explicitly
in the package cohort so the live and installed systems can load Marvell Wi-Fi
firmware. By default the five runtime source
checkouts go beside this repository. Use `--runtime-repos` to point at another
parent directory and `--installer-build` for the paired runtime package summary.
Use `--recovery-env-build` to include a separately built recovery environment.
Prepare the release Flatpak inputs from the signed enzimOS repository:

```sh
python3 -B prepare_flatpak_media.py --output /path/to/new-flatpak-media \
  --flathub-descriptor /path/to/flathub.flatpakrepo
```

Pass its `flathub/` and `enzimos/` directories as `--flatpak` and
`--enzimos-flatpak`. The installer keeps the online remotes as the apps’
origins and installs the selected refs and runtimes from the media. Use
installer 0.2.0-5 or newer, which installs the full native package set in one
transaction, and the native Files, Terminal, Text and Store packages. Task Manager comes from the signed Flatpak fleet. Historical
images can still be assembled with their original reviewed inputs.

The build and VM scripts require the corresponding Linux tools, such as
bubblewrap, makepkg, QEMU and firmware. Use a fresh output directory for each
run. A development image still needs separate release and hardware qualification.

## VM scenarios

Some explicit scenarios need additional input paths.

| Scenario | Input |
| --- | --- |
| `delivery-display-theme` | `ENZIMOS_VM_THEME_SCRIPT` for the Plymouth script |
| `delivery-enroll` | `ENZIMOS_VM_MEDIA_OWNER_CERTIFICATE` for the public certificate |
| `desktop-refresh-stage` | `ENZIMOS_VM_DESKTOP_STAGE` for the staged desktop |
| `mcp-center` | `ENZIMOS_VM_MCP_BUILD_SUMMARY` for the reviewed runtime summary |

Development images with an injected SSH key use guest port `22222`. Set
`ENZIMOS_VM_SSH_GUEST_PORT=22222` and choose the local loopback forward with
`ENZIMOS_VM_SSH_PORT`. The older desktop scenarios exercise their original
fixture media. Use synthetic credentials in VM fixtures.

The backup qualification tools take explicit paths. For app backups, supply
`--baseline`, `--toolroot` and `--trust-lock`. For SMB backups, supply
`--source`, `--keyring` and `--trust-lock`.

Set `ENZIMOS_LAB_LIMITS=1` to opt in to lower-priority serial lab jobs. Set
`ENZIMOS_BUILD_RESERVE_GIB` to reserve additional disk space.

## License

[MIT](LICENSE)
