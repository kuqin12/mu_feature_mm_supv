;------------------------------------------------------------------------------
;
; Copyright (c) Microsoft Corporation.
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Abstract:
;
;   This file provides macro definitions for stack cookie injection and check functions.
;   The null implementation is specific for GCC compilers.
;
;   The users should maintain the sanity of stack alignment and balance when using these
;   macros.
;
;------------------------------------------------------------------------------

;
; Macro for the INJECT_COOKIE step:
;   Registers impacted: None;
;   Stack displacement: Up by 0x10;
;
%macro INJECT_COOKIE       0
    sub     rsp, 0x10
%endmacro

;
; Macro for the CHECK_COOKIE step:
;   Registers impacted: None;
;   Stack displacement: Down by 0x10
;
%macro CHECK_COOKIE       0
    add     rsp, 0x10
%endmacro
