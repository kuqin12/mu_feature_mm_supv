;------------------------------------------------------------------------------
;
; Copyright (c) Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Abstract:
;
;   This file provides macro definitions for stack cookie injection and check functions.
;   The implementation is specific for MSVC compilers.
;
;   The users should maintain the sanity of stack alignment and balance when using these
;   macros.
;
;------------------------------------------------------------------------------

extern __security_check_cookie
extern __security_cookie

;
; Macro for the INJECT_COOKIE step:
;   Registers impacted: RAX;
;   Stack displacement: Up by 0x10;
;
%macro INJECT_COOKIE      0
    sub     rsp, 0x10
    mov     rax, [__security_cookie]
    xor     rax, rsp
    mov     [rsp+8], rax
%endmacro

;
; Macro for the CHECK_COOKIE step:
;   Registers impacted: RCX;
;   Stack displacement: Down by 0x10
;
%macro CHECK_COOKIE       0
    mov     rcx, [rsp+8]
    xor     rcx, rsp
    call    __security_check_cookie
    add     rsp, 0x10
%endmacro
