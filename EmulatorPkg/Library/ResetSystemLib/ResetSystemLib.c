/** @file
  A instance of the ResetSystemLib for EmulatorPkg.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/ResetSystemLib.h>
#include <Library/PeiServicesLib.h>

#include <Ppi/EmuThunk.h>
#include <Protocol/EmuThunk.h>

EFI_STATUS
WinNtReset (
    VOID
)
{
  EFI_STATUS          Status;
  EMU_THUNK_PPI       *ThunkPpi;
  EMU_THUNK_PROTOCOL  *Thunk;
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
    Thunk  = (EMU_THUNK_PROTOCOL *)ThunkPpi->Thunk ();
    Thunk->Exit (0);
  }

  return Status;
}


/**
  This function causes a system-wide reset (cold reset), in which
  all circuitry within the system returns to its initial state. This type of reset
  is asynchronous to system operation and operates without regard to
  cycle boundaries.

  If this function returns, it means that the system does not support cold reset.
**/
VOID
EFIAPI
ResetCold (
  VOID
  )
{
  WinNtReset ();
}

/**
  This function causes a system-wide initialization (warm reset), in which all processors
  are set to their initial state. Pending cycles are not corrupted.

  If this function returns, it means that the system does not support warm reset.
**/
VOID
EFIAPI
ResetWarm (
  VOID
  )
{
  WinNtReset ();
}

/**
  This function causes the system to enter a power state equivalent
  to the ACPI G2/S5 or G3 states.

  If this function returns, it means that the system does not support shut down reset.
**/
VOID
EFIAPI
ResetShutdown (
  VOID
  )
{
  WinNtReset ();
}

/**
  This function causes the system to enter S3 and then wake up immediately.

  If this function returns, it means that the system does not support S3 feature.
**/
VOID
EFIAPI
EnterS3WithImmediateWake (
  VOID
  )
{
  WinNtReset ();
}

/**
  This function causes a systemwide reset. The exact type of the reset is
  defined by the EFI_GUID that follows the Null-terminated Unicode string passed
  into ResetData. If the platform does not recognize the EFI_GUID in ResetData
  the platform must pick a supported reset type to perform.The platform may
  optionally log the parameters from any non-normal reset that occurs.

  @param[in]  DataSize   The size, in bytes, of ResetData.
  @param[in]  ResetData  The data buffer starts with a Null-terminated string,
                         followed by the EFI_GUID.
**/
VOID
EFIAPI
ResetPlatformSpecific (
  IN UINTN   DataSize,
  IN VOID    *ResetData
  )
{
  WinNtReset ();
}
