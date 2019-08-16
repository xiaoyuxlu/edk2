/** @file
  export global variable gWinNtSocket.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/ResetSystemLib.h>
#include <Library/PeiServicesLib.h>

#include <Ppi/EmuThunk.h>
#include "Win/Host/WinInclude.h"
#include <Protocol/EmuSocket.h>

EMU_SOCKET_THUNK_PROTOCOL *gWinNtSocket;

EFI_STATUS
PeiEmuSocketLibConstructor (
  IN EFI_PEI_FILE_HANDLE     FileHandle,
  IN CONST EFI_PEI_SERVICES  **PeiServices
)
{
  EFI_STATUS          Status;
  EMU_THUNK_PPI       *ThunkPpi;
  //
  // Locate EmuThunkPpi for
  //
  Status = PeiServicesLocatePpi (
              &gEmuThunkPpiGuid,
              0,
              NULL,
              (VOID **) &ThunkPpi
             );
  if (!EFI_ERROR (Status)) {
    gWinNtSocket  = (EMU_SOCKET_THUNK_PROTOCOL *)ThunkPpi->SocketThunk ();

  } else {
    gWinNtSocket = NULL;
  }

  return Status;
}
