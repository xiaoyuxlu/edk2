/** @file
  DXE Core Main Entry Point

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeMain.h"

//
// DXE Core globals for Architecture Protocols
//
EFI_SECURITY_ARCH_PROTOCOL        *gSecurity      = NULL;
EFI_SECURITY2_ARCH_PROTOCOL       *gSecurity2     = NULL;
EFI_CPU_ARCH_PROTOCOL             *gCpu           = NULL;
EFI_METRONOME_ARCH_PROTOCOL       *gMetronome     = NULL;
EFI_TIMER_ARCH_PROTOCOL           *gTimer         = NULL;
EFI_BDS_ARCH_PROTOCOL             *gBds           = NULL;
EFI_WATCHDOG_TIMER_ARCH_PROTOCOL  *gWatchdogTimer = NULL;

//
// DXE Core Global used to update core loaded image protocol handle
//
EFI_GUID                           *gDxeCoreFileName;
EFI_LOADED_IMAGE_PROTOCOL          *gDxeCoreLoadedImage;

//
// DXE Core Module Variables
//
EFI_BOOT_SERVICES mBootServices = {
  {
    EFI_BOOT_SERVICES_SIGNATURE,                                                          // Signature
    EFI_BOOT_SERVICES_REVISION,                                                           // Revision
    sizeof (EFI_BOOT_SERVICES),                                                           // HeaderSize
    0,                                                                                    // CRC32
    0                                                                                     // Reserved
  },
  (EFI_RAISE_TPL)                               CoreRaiseTpl,                             // RaiseTPL
  (EFI_RESTORE_TPL)                             CoreRestoreTpl,                           // RestoreTPL
  (EFI_ALLOCATE_PAGES)                          CoreAllocatePages,                        // AllocatePages
  (EFI_FREE_PAGES)                              CoreFreePages,                            // FreePages
  (EFI_GET_MEMORY_MAP)                          CoreGetMemoryMap,                         // GetMemoryMap
  (EFI_ALLOCATE_POOL)                           CoreAllocatePool,                         // AllocatePool
  (EFI_FREE_POOL)                               CoreFreePool,                             // FreePool
  (EFI_CREATE_EVENT)                            CoreCreateEvent,                          // CreateEvent
  (EFI_SET_TIMER)                               CoreSetTimer,                             // SetTimer
  (EFI_WAIT_FOR_EVENT)                          CoreWaitForEvent,                         // WaitForEvent
  (EFI_SIGNAL_EVENT)                            CoreSignalEvent,                          // SignalEvent
  (EFI_CLOSE_EVENT)                             CoreCloseEvent,                           // CloseEvent
  (EFI_CHECK_EVENT)                             CoreCheckEvent,                           // CheckEvent
  (EFI_INSTALL_PROTOCOL_INTERFACE)              CoreInstallProtocolInterface,             // InstallProtocolInterface
  (EFI_REINSTALL_PROTOCOL_INTERFACE)            CoreReinstallProtocolInterface,           // ReinstallProtocolInterface
  (EFI_UNINSTALL_PROTOCOL_INTERFACE)            CoreUninstallProtocolInterface,           // UninstallProtocolInterface
  (EFI_HANDLE_PROTOCOL)                         CoreHandleProtocol,                       // HandleProtocol
  (VOID *)                                      NULL,                                     // Reserved
  (EFI_REGISTER_PROTOCOL_NOTIFY)                CoreRegisterProtocolNotify,               // RegisterProtocolNotify
  (EFI_LOCATE_HANDLE)                           CoreLocateHandle,                         // LocateHandle
  (EFI_LOCATE_DEVICE_PATH)                      CoreLocateDevicePath,                     // LocateDevicePath
  (EFI_INSTALL_CONFIGURATION_TABLE)             CoreInstallConfigurationTable,            // InstallConfigurationTable
  (EFI_IMAGE_LOAD)                              CoreLoadImage,                            // LoadImage
  (EFI_IMAGE_START)                             CoreStartImage,                           // StartImage
  (EFI_EXIT)                                    CoreExit,                                 // Exit
  (EFI_IMAGE_UNLOAD)                            CoreUnloadImage,                          // UnloadImage
  (EFI_EXIT_BOOT_SERVICES)                      CoreExitBootServices,                     // ExitBootServices
  (EFI_GET_NEXT_MONOTONIC_COUNT)                CoreEfiNotAvailableYetArg1,               // GetNextMonotonicCount
  (EFI_STALL)                                   CoreStall,                                // Stall
  (EFI_SET_WATCHDOG_TIMER)                      CoreSetWatchdogTimer,                     // SetWatchdogTimer
  (EFI_CONNECT_CONTROLLER)                      CoreConnectController,                    // ConnectController
  (EFI_DISCONNECT_CONTROLLER)                   CoreDisconnectController,                 // DisconnectController
  (EFI_OPEN_PROTOCOL)                           CoreOpenProtocol,                         // OpenProtocol
  (EFI_CLOSE_PROTOCOL)                          CoreCloseProtocol,                        // CloseProtocol
  (EFI_OPEN_PROTOCOL_INFORMATION)               CoreOpenProtocolInformation,              // OpenProtocolInformation
  (EFI_PROTOCOLS_PER_HANDLE)                    CoreProtocolsPerHandle,                   // ProtocolsPerHandle
  (EFI_LOCATE_HANDLE_BUFFER)                    CoreLocateHandleBuffer,                   // LocateHandleBuffer
  (EFI_LOCATE_PROTOCOL)                         CoreLocateProtocol,                       // LocateProtocol
  (EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES)    CoreInstallMultipleProtocolInterfaces,    // InstallMultipleProtocolInterfaces
  (EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)  CoreUninstallMultipleProtocolInterfaces,  // UninstallMultipleProtocolInterfaces
  (EFI_CALCULATE_CRC32)                         CoreEfiNotAvailableYetArg3,               // CalculateCrc32
  (EFI_COPY_MEM)                                CopyMem,                                  // CopyMem
  (EFI_SET_MEM)                                 SetMem,                                   // SetMem
  (EFI_CREATE_EVENT_EX)                         CoreCreateEventEx                         // CreateEventEx
};

EFI_SYSTEM_TABLE mEfiSystemTableTemplate = {
  {
    EFI_SYSTEM_TABLE_SIGNATURE,                                           // Signature
    EFI_SYSTEM_TABLE_REVISION,                                            // Revision
    sizeof (EFI_SYSTEM_TABLE),                                            // HeaderSize
    0,                                                                    // CRC32
    0                                                                     // Reserved
  },
  NULL,                                                                   // FirmwareVendor
  0,                                                                      // FirmwareRevision
  NULL,                                                                   // ConsoleInHandle
  NULL,                                                                   // ConIn
  NULL,                                                                   // ConsoleOutHandle
  NULL,                                                                   // ConOut
  NULL,                                                                   // StandardErrorHandle
  NULL,                                                                   // StdErr
  NULL,                                                                   // RuntimeServices
  &mBootServices,                                                         // BootServices
  0,                                                                      // NumberOfConfigurationTableEntries
  NULL                                                                    // ConfigurationTable
};

EFI_RUNTIME_SERVICES mEfiRuntimeServicesTableTemplate = {
  {
    EFI_RUNTIME_SERVICES_SIGNATURE,                               // Signature
    EFI_RUNTIME_SERVICES_REVISION,                                // Revision
    sizeof (EFI_RUNTIME_SERVICES),                                // HeaderSize
    0,                                                            // CRC32
    0                                                             // Reserved
  },
  (EFI_GET_TIME)                    CoreEfiNotAvailableYetArg2,   // GetTime
  (EFI_SET_TIME)                    CoreEfiNotAvailableYetArg1,   // SetTime
  (EFI_GET_WAKEUP_TIME)             CoreEfiNotAvailableYetArg3,   // GetWakeupTime
  (EFI_SET_WAKEUP_TIME)             CoreEfiNotAvailableYetArg2,   // SetWakeupTime
  (EFI_SET_VIRTUAL_ADDRESS_MAP)     CoreEfiNotAvailableYetArg4,   // SetVirtualAddressMap
  (EFI_CONVERT_POINTER)             CoreEfiNotAvailableYetArg2,   // ConvertPointer
  (EFI_GET_VARIABLE)                CoreEfiNotAvailableYetArg5,   // GetVariable
  (EFI_GET_NEXT_VARIABLE_NAME)      CoreEfiNotAvailableYetArg3,   // GetNextVariableName
  (EFI_SET_VARIABLE)                CoreEfiNotAvailableYetArg5,   // SetVariable
  (EFI_GET_NEXT_HIGH_MONO_COUNT)    CoreEfiNotAvailableYetArg1,   // GetNextHighMonotonicCount
  (EFI_RESET_SYSTEM)                CoreEfiNotAvailableYetArg4,   // ResetSystem
  (EFI_UPDATE_CAPSULE)              CoreEfiNotAvailableYetArg3,   // UpdateCapsule
  (EFI_QUERY_CAPSULE_CAPABILITIES)  CoreEfiNotAvailableYetArg4,   // QueryCapsuleCapabilities
  (EFI_QUERY_VARIABLE_INFO)         CoreEfiNotAvailableYetArg4    // QueryVariableInfo
};

EFI_RUNTIME_ARCH_PROTOCOL gRuntimeTemplate = {
  INITIALIZE_LIST_HEAD_VARIABLE (gRuntimeTemplate.ImageHead),
  INITIALIZE_LIST_HEAD_VARIABLE (gRuntimeTemplate.EventHead),

  //
  // Make sure Size != sizeof (EFI_MEMORY_DESCRIPTOR). This will
  // prevent people from having pointer math bugs in their code.
  // now you have to use *DescriptorSize to make things work.
  //
  sizeof (EFI_MEMORY_DESCRIPTOR) + sizeof (UINT64) - (sizeof (EFI_MEMORY_DESCRIPTOR) % sizeof (UINT64)),
  EFI_MEMORY_DESCRIPTOR_VERSION,
  0,
  NULL,
  NULL,
  FALSE,
  FALSE
};

EFI_RUNTIME_ARCH_PROTOCOL *gRuntime = &gRuntimeTemplate;

//
// DXE Core Global Variables for the EFI System Table, Boot Services Table,
// and Runtime Services Table
//
EFI_SYSTEM_TABLE      *gDxeCoreST = NULL;

//
// For debug initialize gDxeCoreRT to template. gDxeCoreRT must be allocated from RT memory
//  but gDxeCoreRT is used for ASSERT () and DEBUG () type macros so lets give it
//  a value that will not cause debug infrastructure to crash early on.
//
EFI_RUNTIME_SERVICES  *gDxeCoreRT = &mEfiRuntimeServicesTableTemplate;
EFI_HANDLE            gDxeCoreImageHandle = NULL;

BOOLEAN               gMemoryMapTerminated = FALSE;

// Main entry point to the DXE Core
//

/**
  Main entry point to DXE Core.

  @param  HobStart               Pointer to the beginning of the HOB List from PEI.

  @return This function should never return.

**/
VOID
EFIAPI
DxeMain (
  IN  VOID *HobStart
  )
{
  EFI_STATUS                    Status;
  EFI_PHYSICAL_ADDRESS          MemoryBaseAddress;
  UINT64                        MemoryLength;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  VOID                          *EntryPoint;

  DEBUG ((DEBUG_INFO, "CoreInitializeMemoryServices\n"));

  //
  // Initialize Memory Services
  //
  CoreInitializeMemoryServices (&HobStart, &MemoryBaseAddress, &MemoryLength);

  //
  // Allocate the EFI System Table and EFI Runtime Service Table from EfiRuntimeServicesData
  // Use the templates to initialize the contents of the EFI System Table and EFI Runtime Services Table
  //
  gDxeCoreST = AllocateRuntimeCopyPool (sizeof (EFI_SYSTEM_TABLE), &mEfiSystemTableTemplate);
  ASSERT (gDxeCoreST != NULL);

  gDxeCoreRT = AllocateRuntimeCopyPool (sizeof (EFI_RUNTIME_SERVICES), &mEfiRuntimeServicesTableTemplate);
  ASSERT (gDxeCoreRT != NULL);

  gDxeCoreST->RuntimeServices = gDxeCoreRT;

  DEBUG ((DEBUG_INFO, "CoreInitializeImageServices\n"));

  //
  // Start the Image Services.
  //
  Status = CoreInitializeImageServices (HobStart);
  ASSERT_EFI_ERROR (Status);
  
  DEBUG ((DEBUG_INFO, "CoreInitializeGcdServices\n"));

  //
  // Initialize the Global Coherency Domain Services
  //
  Status = CoreInitializeGcdServices (&HobStart, MemoryBaseAddress, MemoryLength);
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_INFO, "ProcessLibraryConstructorList\n"));

  //
  // Call constructor for all libraries
  //
  ProcessLibraryConstructorList (gDxeCoreImageHandle, gDxeCoreST);

  //
  // Report DXE Core image information to the PE/COFF Extra Action Library
  //
  ZeroMem (&ImageContext, sizeof (ImageContext));
  ImageContext.ImageAddress   = (EFI_PHYSICAL_ADDRESS)(UINTN)gDxeCoreLoadedImage->ImageBase;
  ImageContext.PdbPointer     = PeCoffLoaderGetPdbPointer ((VOID*)(UINTN)ImageContext.ImageAddress);
  ImageContext.SizeOfHeaders  = PeCoffGetSizeOfHeaders ((VOID*)(UINTN)ImageContext.ImageAddress);
  Status = PeCoffLoaderGetEntryPoint ((VOID*)(UINTN)ImageContext.ImageAddress, &EntryPoint);
  if (Status == EFI_SUCCESS) {
    ImageContext.EntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)EntryPoint;
  }
  ImageContext.Handle         = (VOID *)(UINTN)gDxeCoreLoadedImage->ImageBase;
  ImageContext.ImageRead      = PeCoffLoaderImageReadFromMemory;
  PeCoffLoaderRelocateImageExtraAction (&ImageContext);
  
  DEBUG ((DEBUG_INFO, "CoreInstallConfigurationTable (Hob)\n"));

  //
  // Install the HOB List into the EFI System Tables's Configuration Table
  //
  Status = CoreInstallConfigurationTable (&gEfiHobListGuid, HobStart);
  ASSERT_EFI_ERROR (Status);
  
  DEBUG ((DEBUG_INFO, "CoreInstallConfigurationTable (MemTypeInfo)\n"));

  //
  // Install Memory Type Information Table into the EFI System Tables's Configuration Table
  //
  Status = CoreInstallConfigurationTable (&gEfiMemoryTypeInformationGuid, &gMemoryTypeInformation);
  ASSERT_EFI_ERROR (Status);

  DEBUG ((DEBUG_INFO | DEBUG_LOAD, "HOBLIST address in DXE = 0x%p\n", HobStart));

  DEBUG_CODE_BEGIN ();
    EFI_PEI_HOB_POINTERS               Hob;

    for (Hob.Raw = HobStart; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
      if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
        DEBUG ((DEBUG_INFO | DEBUG_LOAD, "Memory Allocation 0x%08x 0x%0lx - 0x%0lx\n", \
          Hob.MemoryAllocation->AllocDescriptor.MemoryType,                      \
          Hob.MemoryAllocation->AllocDescriptor.MemoryBaseAddress,               \
          Hob.MemoryAllocation->AllocDescriptor.MemoryBaseAddress + Hob.MemoryAllocation->AllocDescriptor.MemoryLength - 1));
      }
    }
    for (Hob.Raw = HobStart; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
      if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV) {
        DEBUG ((
          DEBUG_INFO | DEBUG_LOAD,
          "FV Hob            0x%0lx - 0x%0lx\n",
          Hob.FirmwareVolume->BaseAddress,
          Hob.FirmwareVolume->BaseAddress + Hob.FirmwareVolume->Length - 1
          ));
      } else if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV2) {
        DEBUG ((
          DEBUG_INFO | DEBUG_LOAD,
          "FV2 Hob           0x%0lx - 0x%0lx\n",
          Hob.FirmwareVolume2->BaseAddress,
          Hob.FirmwareVolume2->BaseAddress + Hob.FirmwareVolume2->Length - 1
          ));
        DEBUG ((
          DEBUG_INFO | DEBUG_LOAD,
          "                  %g - %g\n",
          &Hob.FirmwareVolume2->FvName,
          &Hob.FirmwareVolume2->FileName
          ));
      } else if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_FV3) {
        DEBUG ((
          DEBUG_INFO | DEBUG_LOAD,
          "FV3 Hob           0x%0lx - 0x%0lx - 0x%x - 0x%x\n",
          Hob.FirmwareVolume3->BaseAddress,
          Hob.FirmwareVolume3->BaseAddress + Hob.FirmwareVolume3->Length - 1,
          Hob.FirmwareVolume3->AuthenticationStatus,
          Hob.FirmwareVolume3->ExtractedFv
          ));
        if (Hob.FirmwareVolume3->ExtractedFv) {
          DEBUG ((
            DEBUG_INFO | DEBUG_LOAD,
            "                  %g - %g\n",
            &Hob.FirmwareVolume3->FvName,
            &Hob.FirmwareVolume3->FileName
            ));
        }
      }
    }
  DEBUG_CODE_END ();

  //
  // Initialize the Event Services
  //
  Status = CoreInitializeEventServices ();
  ASSERT_EFI_ERROR (Status);

  //
  // Register for the GUIDs of the Architectural Protocols, so the rest of the
  // EFI Boot Services and EFI Runtime Services tables can be filled in.
  // Also register for the GUIDs of optional protocols.
  //
  CoreNotifyOnProtocolInstallation ();

  //
  // Invoke the DXE Dispatcher
  //
  // TBD: Add driver-lib entrypoint here.
  //

  //
  // Display Architectural protocols that were not loaded if this is DEBUG build
  //
  DEBUG_CODE_BEGIN ();
    CoreDisplayMissingArchProtocols ();
  DEBUG_CODE_END ();

  //
  // Assert if the Architectural Protocols are not present.
  //
  Status = CoreAllEfiServicesAvailable ();
  ASSERT_EFI_ERROR (Status);

  //
  // Transfer control to the BDS Architectural Protocol
  //
  gBds->Entry (gBds);

  //
  // BDS should never return
  //
  ASSERT (FALSE);
  CpuDeadLoop ();

  UNREACHABLE ();
}




/**
  Place holder function until all the Boot Services and Runtime Services are
  available.

  @param  Arg1                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg1 (
  UINTN Arg1
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg2 (
  UINTN Arg1,
  UINTN Arg2
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg3 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg4 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}


/**
  Place holder function until all the Boot Services and Runtime Services are available.

  @param  Arg1                   Undefined
  @param  Arg2                   Undefined
  @param  Arg3                   Undefined
  @param  Arg4                   Undefined
  @param  Arg5                   Undefined

  @return EFI_NOT_AVAILABLE_YET

**/
EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg5 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4,
  UINTN Arg5
  )
{
  //
  // This function should never be executed.  If it does, then the architectural protocols
  // have not been designed correctly.  The CpuBreakpoint () is commented out for now until the
  // DXE Core and all the Architectural Protocols are complete.
  //

  return EFI_NOT_AVAILABLE_YET;
}


/**
  Calcualte the 32-bit CRC in a EFI table using the service provided by the
  gRuntime service.

  @param  Hdr                    Pointer to an EFI standard header

**/
VOID
CalculateEfiHdrCrc (
  IN  OUT EFI_TABLE_HEADER    *Hdr
  )
{
  UINT32 Crc;

  Hdr->CRC32 = 0;

  //
  // If gBS->CalculateCrce32 () == CoreEfiNotAvailableYet () then
  //  Crc will come back as zero if we set it to zero here
  //
  Crc = 0;
  gBS->CalculateCrc32 ((UINT8 *)Hdr, Hdr->HeaderSize, &Crc);
  Hdr->CRC32 = Crc;
}


/**
  Terminates all boot services.

  @param  ImageHandle            Handle that identifies the exiting image.
  @param  MapKey                 Key to the latest memory map.

  @retval EFI_SUCCESS            Boot Services terminated
  @retval EFI_INVALID_PARAMETER  MapKey is incorrect.

**/
EFI_STATUS
EFIAPI
CoreExitBootServices (
  IN EFI_HANDLE   ImageHandle,
  IN UINTN        MapKey
  )
{
  EFI_STATUS                Status;

  //
  // Disable Timer
  //
  gTimer->SetTimerPeriod (gTimer, 0);

  //
  // Terminate memory services if the MapKey matches
  //
  Status = CoreTerminateMemoryMap (MapKey);
  if (EFI_ERROR (Status)) {
    //
    // Notify other drivers that ExitBootServices fail
    //
    CoreNotifySignalList (&gEventExitBootServicesFailedGuid);
    return Status;
  }

  gMemoryMapTerminated = TRUE;

  //
  // Notify other drivers that we are exiting boot services.
  //
  CoreNotifySignalList (&gEfiEventExitBootServicesGuid);

  //
  // Disable CPU Interrupts
  //
  gCpu->DisableInterrupt (gCpu);

  //
  // Clear the non-runtime values of the EFI System Table
  //
  gDxeCoreST->BootServices        = NULL;
  gDxeCoreST->ConIn               = NULL;
  gDxeCoreST->ConsoleInHandle     = NULL;
  gDxeCoreST->ConOut              = NULL;
  gDxeCoreST->ConsoleOutHandle    = NULL;
  gDxeCoreST->StdErr              = NULL;
  gDxeCoreST->StandardErrorHandle = NULL;

  //
  // Recompute the 32-bit CRC of the EFI System Table
  //
  CalculateEfiHdrCrc (&gDxeCoreST->Hdr);

  //
  // Zero out the Boot Service Table
  //
  ZeroMem (gBS, sizeof (EFI_BOOT_SERVICES));
  gBS = NULL;

  //
  // Update the AtRuntime field in Runtiem AP.
  //
  gRuntime->AtRuntime = TRUE;

  return Status;
}

