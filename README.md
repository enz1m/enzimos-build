# enzimOS Build Tools

Tools for checking enzimOS manifests, preparing package inputs, assembling
development installation media and running integration checks in disposable VMs.

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
desktop with the graphical installer. By default the five runtime source
checkouts go beside this repository. Use `--runtime-repos` to point at another
parent directory and `--installer-build` for the paired runtime package summary.
Use `--recovery-env-build` to include a separately built recovery environment.
The current installer expects a Flathub application declaration when enzimOS
Flatpaks are included. A media layout with only enzimOS apps and Flathub
runtimes requires installer support.

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
