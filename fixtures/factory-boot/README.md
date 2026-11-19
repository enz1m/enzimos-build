# Factory-chain firmware fixture

`probe.c` is an authored firmware-only probe, not an OS loader or kernel.
It is compiled against the exact shim release's bundled GNU EFI and uses the debug
port to record its own execution. The explicit lab driver lives in the local
workspace archive; no unit test starts a VM, generates keys or enrolls firmware.

In a new private OVMF variable store, `ENROLL` refuses outside Setup Mode and writes
only the disposable lab `db` and `PK`. `certificates.h` is generated from the lab
public certificate as an EFI signature list with a Setup Mode authentication header.
`REVOKE` additionally sets a lab SBAT floor with boot-service-only attributes;
`DBX` puts the disposable firmware certificate in dbx to exercise firmware denial. None of this is installed or run on the
host. Never compile production certificates into this enrollment fixture.

The child probe succeeds only with `SecureBoot=1` and the shim lock protocol
present. Its signed, unsigned, unrelated-certificate, modified and SBAT-revoked
variants exercise the real chain. Negative phases must record the actual firmware/
shim rejection and absence of the child marker; a timeout alone is insufficient.

The fixture proves lab trust enforcement for this EFI probe only. It does not
qualify Microsoft factory trust, systemd-boot, Linux lockdown, modules, generic
root discovery, installed OS/recovery, physical firmware, Windows or NVIDIA.
