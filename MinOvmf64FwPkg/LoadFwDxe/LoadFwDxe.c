/** @file
  Sample ACPI Platform Driver

  Copyright (c) 2008 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Protocol/FirmwareVolume2.h>

#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/PciLib.h>
#include <Library/ElfLoaderLib.h>

EFI_GUID mFwGuid = {
  0x345e675, 0x6e19, 0x40e1, {0x9f, 0xdd, 0x6e, 0x6, 0xf2, 0x63, 0x8f, 0xb7}
};

typedef
VOID
(EFIAPI *EFI_DXE_CORE_ENTRY_POINT) (
  IN CONST EFI_PEI_HOB_POINTERS *HobList
  );

/**
  Locate the first instance of a protocol.  If the protocol requested is an
  FV protocol, then it will return the first FV that contains the ACPI table
  storage file.

  @param  Instance      Return pointer to the first instance of the protocol

  @return EFI_SUCCESS           The function completed successfully.
  @return EFI_NOT_FOUND         The protocol could not be located.
  @return EFI_OUT_OF_RESOURCES  There are not enough resources to find the protocol.

**/
EFI_STATUS
LocateFvInstanceWithTables (
  OUT EFI_FIRMWARE_VOLUME2_PROTOCOL **Instance
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    *HandleBuffer;
  UINTN                         NumberOfHandles;
  EFI_FV_FILETYPE               FileType;
  UINT32                        FvStatus;
  EFI_FV_FILE_ATTRIBUTES        Attributes;
  UINTN                         Size;
  UINTN                         Index;
  EFI_FIRMWARE_VOLUME2_PROTOCOL *FvInstance;

  FvStatus = 0;

  //
  // Locate protocol.
  //
  Status = gBS->LocateHandleBuffer (
                   ByProtocol,
                   &gEfiFirmwareVolume2ProtocolGuid,
                   NULL,
                   &NumberOfHandles,
                   &HandleBuffer
                   );
  if (EFI_ERROR (Status)) {
    //
    // Defined errors at this time are not found and out of resources.
    //
    return Status;
  }



  //
  // Looking for FV with ACPI storage file
  //

  for (Index = 0; Index < NumberOfHandles; Index++) {
    //
    // Get the protocol on this handle
    // This should not fail because of LocateHandleBuffer
    //
    Status = gBS->HandleProtocol (
                     HandleBuffer[Index],
                     &gEfiFirmwareVolume2ProtocolGuid,
                     (VOID**) &FvInstance
                     );
    ASSERT_EFI_ERROR (Status);

    //
    // See if it has the ACPI storage file
    //
    Status = FvInstance->ReadFile (
                           FvInstance,
                           (EFI_GUID*)&mFwGuid,
                           NULL,
                           &Size,
                           &FileType,
                           &Attributes,
                           &FvStatus
                           );

    //
    // If we found it, then we are done
    //
    if (Status == EFI_SUCCESS) {
      *Instance = FvInstance;
      break;
    }
  }

  //
  // Our exit status is determined by the success of the previous operations
  // If the protocol was found, Instance already points to it.
  //

  //
  // Free any allocated buffers
  //
  gBS->FreePool (HandleBuffer);

  return Status;
}

VOID
DumpPci (
  IN UINT8 Bus,
  IN UINT8 Device,
  IN UINT8 Function
  )
{
  UINTN  Index;
  UINTN  SubIndex;

  DEBUG ((DEBUG_INFO, "B%02x.D%02x.F%02x:\n", Bus, Device, Function));
  for (Index = 0; Index < 0x100; Index+=0x10) {
    UINT8   CacheData[0x10];
    for (SubIndex = 0; SubIndex < 0x10; SubIndex+=4) {
      *(UINT32 *)(CacheData + SubIndex) = PciRead32(PCI_LIB_ADDRESS (Bus, Device, Function, Index + SubIndex));
    }

    DEBUG ((DEBUG_INFO, "0x%02x : ", Index));
    for (SubIndex = 0; SubIndex < 0x10; SubIndex++) {
      DEBUG ((DEBUG_INFO, "%02x", CacheData[SubIndex]));
      if (SubIndex == 7) {
        DEBUG ((DEBUG_INFO, "-"));
      } else {
        DEBUG ((DEBUG_INFO, " "));
      }
    }
    DEBUG ((DEBUG_INFO, "\n"));
  }
}


/**
  Entrypoint of Acpi Platform driver.

  @param  ImageHandle
  @param  SystemTable

  @return EFI_SUCCESS
  @return EFI_LOAD_ERROR
  @return EFI_OUT_OF_RESOURCES

**/
EFI_STATUS
EFIAPI
LoadFwDxeEntryPoint (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS                     Status;
  EFI_FIRMWARE_VOLUME2_PROTOCOL  *FwVol;
  UINT32                         FvStatus;
  UINTN                          HypervisorFwImageSize;
  VOID                           *HypervisorFwImageBase;
  UINTN                          HypervisorFwEntryPoint;
  VOID                           *BaseHypervisorFw;
  UINTN                          Size;

  DumpPci (0, 3, 0);

  //
  // Locate the firmware volume protocol
  //
  Status = LocateFvInstanceWithTables (&FwVol);
  ASSERT_EFI_ERROR (Status);
  //
  // Read tables from the storage file.
  //
  Status = FwVol->ReadSection (
                    FwVol,
                    (EFI_GUID*)&mFwGuid,
                    EFI_SECTION_RAW,
                    0,
                    (VOID**) &HypervisorFwImageBase,
                    &HypervisorFwImageSize,
                    &FvStatus
                    );
  ASSERT_EFI_ERROR (Status);

  ASSERT(*(UINT32*)(UINTN)HypervisorFwImageBase == *(UINT32 *)ELFMAG);
  DEBUG ((DEBUG_ERROR, "ELF FW Image\n"));
  DEBUG ((DEBUG_ERROR, "HypervisorFwImageBase - 0x%x\n", HypervisorFwImageBase));
  DumpElf ((VOID *)(UINTN)HypervisorFwImageBase);
  DEBUG ((DEBUG_ERROR, "HypervisorFwImageBase - 0x%x\n", HypervisorFwImageBase));
  Status = GetElfImageInfo ((VOID *)(UINTN)HypervisorFwImageBase, 0, &BaseHypervisorFw, &Size, &HypervisorFwEntryPoint);
  DEBUG ((DEBUG_ERROR, "BaseHypervisorFw - 0x%x\n", BaseHypervisorFw));
  DEBUG ((DEBUG_ERROR, "Size - 0x%x\n", Size));
  DEBUG ((DEBUG_ERROR, "HypervisorFwEntryPoint - 0x%x\n", HypervisorFwEntryPoint));
  ASSERT_EFI_ERROR(Status);
  // AllocateAddress ;
  Status = LoadElfImageData ((VOID *)(UINTN)HypervisorFwImageBase, 0, BaseHypervisorFw, Size, &HypervisorFwEntryPoint);
  ASSERT_EFI_ERROR(Status);
  ((EFI_DXE_CORE_ENTRY_POINT)HypervisorFwEntryPoint) (NULL);

  //
  // The driver does not require to be kept loaded.
  //
  return EFI_REQUEST_UNLOAD_IMAGE;
}

