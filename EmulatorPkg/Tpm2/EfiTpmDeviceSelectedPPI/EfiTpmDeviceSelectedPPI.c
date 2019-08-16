/** @file
  Install gEfiTpmDeviceSelectedGuid PPI for Tcg2Pei module.

Copyright (c) 2019, Intel Corporation. All rights reserved.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <uefi.h>

#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

#include <PiPei.h>
#include <Library/PeiServicesLib.h>

extern EFI_GUID gEfiTpmDeviceSelectedGuid;

EFI_PEI_PPI_DESCRIPTOR      mEfiTpmDeviceSelectedDescriptor = {
  EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
  &gEfiTpmDeviceSelectedGuid,
  NULL,
};

EFI_STATUS
EFIAPI
EfiTpmDeviceSelectedPPIEntry (
  IN        EFI_PEI_FILE_HANDLE   FileHandle,
  IN  CONST EFI_PEI_SERVICES      **PeiServices
)
{
  EFI_STATUS    Status;

  Status = PeiServicesInstallPpi (&mEfiTpmDeviceSelectedDescriptor);

  return Status;
}
