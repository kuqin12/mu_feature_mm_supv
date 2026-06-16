;------------------------------------------------------------------------------
; MmSupervisorEntry.nasm
;
; Assembly entry stub for the MM Supervisor (Init) image.
;
; The PE entry point receives two arguments under the Microsoft x64 calling
; convention from the producer (PEI MM IPL / relay):
;   RCX = FoundationEntryPoint (MM_FOUNDATION_ENTRY_POINT)
;   RDX = HobStart             (VOID *)
;
; This stub exists so the linker /ENTRY can target a symbol that forwards BOTH
; register arguments to the C worker MmSupervisorMain(FoundationEntryPoint,
; HobStart) unchanged. It deliberately does NOT touch RCX/RDX so both arguments
; are preserved exactly as supplied by the caller. A tail jmp is used so the
; caller's return address and stack remain the call frame for MmSupervisorMain.
;
; Copyright (C) Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;------------------------------------------------------------------------------

extern ASM_PFX(MmSupervisorMain)

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; EFI_STATUS
; EFIAPI
; MmSupervisorEntryPoint (
;   IN MM_FOUNDATION_ENTRY_POINT  FoundationEntryPoint,  // RCX
;   IN VOID                       *HobStart              // RDX
;   );
;
; Forwards RCX/RDX untouched to MmSupervisorMain via a tail call.
;------------------------------------------------------------------------------
global ASM_PFX(MmSupervisorEntryPoint)
ASM_PFX(MmSupervisorEntryPoint):
    ;
    ; RCX = FoundationEntryPoint, RDX = HobStart are already positioned for the
    ; MmSupervisorMain(FoundationEntryPoint, HobStart) call. Tail-jump so the
    ; return goes directly back to our caller.
    ;
    jmp ASM_PFX(MmSupervisorMain)
