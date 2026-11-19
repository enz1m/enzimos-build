/* SPDX-License-Identifier: MIT
 * Firmware-only disposable lab probe. No OS disks or production certificates.
 */
#include <efi.h>
#include <efilib.h>
#ifdef ENROLL
#include "certificates.h"
#endif
#ifdef ENROLL
static void code(EFI_STATUS s) {
    const char *hex="0123456789abcdef";
    for (int i=15;i>=0;--i) { unsigned char c=hex[(s>>(i*4))&15]; __asm__ volatile("outb %0,%1" : : "a"(c), "Nd"((unsigned short)0x402)); }
}
#endif
static void message(const char *s) {
    while (*s) { __asm__ volatile("outb %0,%1" : : "a"((unsigned char)*s++), "Nd"((unsigned short)0x402)); }
}
EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *table) {
    InitializeLib(image, table);
    EFI_GUID global = EFI_GLOBAL_VARIABLE;
    UINT8 enabled = 0, setup = 0; UINTN size = 1;
    EFI_STATUS status = uefi_call_wrapper(RT->GetVariable,5,L"SecureBoot",&global,NULL,&size,&enabled);
    if (EFI_ERROR(status)) { message("LAB_BAD_SECUREBOOT_FLAG\n"); return EFI_ABORTED; }
#ifdef ENROLL
    size=1; status=uefi_call_wrapper(RT->GetVariable,5,L"SetupMode",&global,NULL,&size,&setup);
    if (EFI_ERROR(status) || !setup || enabled) { message("LAB_REFUSE_NOT_SETUP\n"); return EFI_ABORTED; }
    EFI_GUID db = {0xd719b2cb,0x3d3a,0x4596,{0xa3,0xbc,0xda,0xd0,0x0e,0x67,0x65,0x6f}};
    UINT32 attr=EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS|0x20;
    status=uefi_call_wrapper(RT->SetVariable,5,L"db",&db,attr,sizeof(firmware_esl),firmware_esl);
    if (EFI_ERROR(status)) { message("LAB_DB_ENROLL_FAILED "); code(status); message("\n"); return status; }
#ifdef DBX
    status=uefi_call_wrapper(RT->SetVariable,5,L"dbx",&db,attr,sizeof(firmware_esl),firmware_esl);
    if (EFI_ERROR(status)) { message("LAB_DBX_ENROLL_FAILED "); code(status); message("\n"); return status; }
#endif
#ifdef REVOKE
    EFI_GUID shim = {0x605dab50,0xe046,0x4300,{0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23}};
    char floor[]="sbat,1,2099123100\nsentinel.enzimos,2\n";
    status=uefi_call_wrapper(RT->SetVariable,5,L"SbatLevel",&shim,EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS,sizeof(floor)-1,floor);
    if (EFI_ERROR(status)) { message("LAB_SBAT_ENROLL_FAILED\n"); return status; }
#endif
    status=uefi_call_wrapper(RT->SetVariable,5,L"PK",&global,attr,sizeof(firmware_esl),firmware_esl);
    if (EFI_ERROR(status)) { message("LAB_PK_ENROLL_FAILED "); code(status); message("\n"); return status; }
    message("LAB_ENROLL_PASS\n");
#else
    (void)setup;
    EFI_GUID shim = {0x605dab50,0xe046,0x4300,{0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23}};
    VOID *protocol=NULL;
    status=uefi_call_wrapper(BS->LocateProtocol,3,&shim,NULL,&protocol);
    if (!enabled || EFI_ERROR(status) || !protocol) { message("LAB_UNTRUSTED_ENTRY\n"); return EFI_ABORTED; }
    message("LAB_SHIM_CHILD_PASS_SECUREBOOT_1\n");
#endif
    uefi_call_wrapper(RT->ResetSystem,4,EfiResetShutdown,EFI_SUCCESS,0,NULL);
    return EFI_SUCCESS;
}
