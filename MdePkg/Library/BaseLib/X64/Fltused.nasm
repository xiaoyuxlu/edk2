;------------------------------------------------------------------------------ ;
; Copyright (c) 2017, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
;------------------------------------------------------------------------------

    DEFAULT REL
    SECTION .text
global ASM_PFX(_fltused)
ASM_PFX(_fltused):
    mov     eax, ecx
    ret

