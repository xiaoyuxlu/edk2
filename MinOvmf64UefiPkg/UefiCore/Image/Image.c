/** @file
  Core image handling services to load and unload PeImage.

Copyright (c) 2006 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeMain.h"
#include "Image.h"

//
// Module Globals
//
LOADED_IMAGE_PRIVATE_DATA  *mCurrentImage = NULL;

//
// This code is needed to build the Image handle for the DXE Core
//
LOADED_IMAGE_PRIVATE_DATA mCorePrivateImage  = {
  LOADED_IMAGE_PRIVATE_DATA_SIGNATURE,            // Signature
  NULL,                                           // Image handle
  EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,    // Image type
  TRUE,                                           // If entrypoint has been called
  NULL, // EntryPoint
  {
    EFI_LOADED_IMAGE_INFORMATION_REVISION,        // Revision
    NULL,                                         // Parent handle
    NULL,                                         // System handle

    NULL,                                         // Device handle
    NULL,                                         // File path
    NULL,                                         // Reserved

    0,                                            // LoadOptionsSize
    NULL,                                         // LoadOptions

    NULL,                                         // ImageBase
    0,                                            // ImageSize
    EfiBootServicesCode,                          // ImageCodeType
    EfiBootServicesData                           // ImageDataType
  },
  (EFI_PHYSICAL_ADDRESS)0,    // ImageBasePage
  0,                          // NumberOfPages
  NULL,                       // FixupData
  0,                          // Tpl
  EFI_SUCCESS,                // Status
  0,                          // ExitDataSize
  NULL,                       // ExitData
  NULL,                       // JumpBuffer
  NULL,                       // JumpContext
  0,                          // Machine
  NULL,                       // RuntimeData
  NULL                        // LoadedImageDevicePath
};
//
// The field is define for Loading modules at fixed address feature to tracker the PEI code
// memory range usage. It is a bit mapped array in which every bit indicates the correspoding memory page
// available or not.
//
GLOBAL_REMOVE_IF_UNREFERENCED    UINT64                *mDxeCodeMemoryRangeUsageBitMap=NULL;

typedef struct {
  UINT16  MachineType;
  CHAR16  *MachineTypeName;
} MACHINE_TYPE_INFO;

GLOBAL_REMOVE_IF_UNREFERENCED MACHINE_TYPE_INFO  mMachineTypeInfo[] = {
  {EFI_IMAGE_MACHINE_IA32,           L"IA32"},
  {EFI_IMAGE_MACHINE_IA64,           L"IA64"},
  {EFI_IMAGE_MACHINE_X64,            L"X64"},
  {EFI_IMAGE_MACHINE_ARMTHUMB_MIXED, L"ARM"},
  {EFI_IMAGE_MACHINE_AARCH64,        L"AARCH64"}
};

UINT16 mDxeCoreImageMachineType = 0;

/**
 Return machine type name.

 @param MachineType The machine type

 @return machine type name
**/
CHAR16 *
GetMachineTypeName (
  UINT16 MachineType
  )
{
  UINTN  Index;

  for (Index = 0; Index < sizeof(mMachineTypeInfo)/sizeof(mMachineTypeInfo[0]); Index++) {
    if (mMachineTypeInfo[Index].MachineType == MachineType) {
      return mMachineTypeInfo[Index].MachineTypeName;
    }
  }

  return L"<Unknown>";
}

/**
  Add the Image Services to EFI Boot Services Table and install the protocol
  interfaces for this image.

  @param  HobStart                The HOB to initialize

  @return Status code.

**/
EFI_STATUS
CoreInitializeImageServices (
  IN  VOID *HobStart
  )
{
  EFI_STATUS                        Status;
  LOADED_IMAGE_PRIVATE_DATA         *Image;
  EFI_PHYSICAL_ADDRESS              DxeCoreImageBaseAddress;
  UINT64                            DxeCoreImageLength;
  VOID                              *DxeCoreEntryPoint;
  EFI_PEI_HOB_POINTERS              DxeCoreHob;

  //
  // Searching for image hob
  //
  DxeCoreHob.Raw          = HobStart;
  while ((DxeCoreHob.Raw = GetNextHob (EFI_HOB_TYPE_MEMORY_ALLOCATION, DxeCoreHob.Raw)) != NULL) {
    if (CompareGuid (&DxeCoreHob.MemoryAllocationModule->MemoryAllocationHeader.Name, &gEfiHobMemoryAllocModuleGuid)) {
      //
      // Find Dxe Core HOB
      //
      break;
    }
    DxeCoreHob.Raw = GET_NEXT_HOB (DxeCoreHob);
  }
  ASSERT (DxeCoreHob.Raw != NULL);

  DxeCoreImageBaseAddress = DxeCoreHob.MemoryAllocationModule->MemoryAllocationHeader.MemoryBaseAddress;
  DxeCoreImageLength      = DxeCoreHob.MemoryAllocationModule->MemoryAllocationHeader.MemoryLength;
  DxeCoreEntryPoint       = (VOID *) (UINTN) DxeCoreHob.MemoryAllocationModule->EntryPoint;
  gDxeCoreFileName        = &DxeCoreHob.MemoryAllocationModule->ModuleName;

  //
  // Initialize the fields for an internal driver
  //
  Image = &mCorePrivateImage;

  Image->EntryPoint         = (EFI_IMAGE_ENTRY_POINT)(UINTN)DxeCoreEntryPoint;
  Image->ImageBasePage      = DxeCoreImageBaseAddress;
  Image->NumberOfPages      = (UINTN)(EFI_SIZE_TO_PAGES((UINTN)(DxeCoreImageLength)));
  Image->Tpl                = gEfiCurrentTpl;
  Image->Info.SystemTable   = gDxeCoreST;
  Image->Info.ImageBase     = (VOID *)(UINTN)DxeCoreImageBaseAddress;
  Image->Info.ImageSize     = DxeCoreImageLength;

  //
  // Install the protocol interfaces for this image
  //
  Status = CoreInstallProtocolInterface (
             &Image->Handle,
             &gEfiLoadedImageProtocolGuid,
             EFI_NATIVE_INTERFACE,
             &Image->Info
             );
  ASSERT_EFI_ERROR (Status);

  mCurrentImage = Image;

  //
  // Fill in DXE globals
  //
  mDxeCoreImageMachineType = PeCoffLoaderGetMachineType (Image->Info.ImageBase);
  gDxeCoreImageHandle = Image->Handle;
  gDxeCoreLoadedImage = &Image->Info;

  return Status;
}

/**
  Read image file (specified by UserHandle) into user specified buffer with specified offset
  and length.

  @param  UserHandle             Image file handle
  @param  Offset                 Offset to the source file
  @param  ReadSize               For input, pointer of size to read; For output,
                                 pointer of size actually read.
  @param  Buffer                 Buffer to write into

  @retval EFI_SUCCESS            Successfully read the specified part of file
                                 into buffer.

**/
EFI_STATUS
EFIAPI
CoreReadImageFile (
  IN     VOID    *UserHandle,
  IN     UINTN   Offset,
  IN OUT UINTN   *ReadSize,
  OUT    VOID    *Buffer
  )
{
  UINTN               EndPosition;
  IMAGE_FILE_HANDLE  *FHand;

  if (UserHandle == NULL || ReadSize == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (MAX_ADDRESS - Offset < *ReadSize) {
    return EFI_INVALID_PARAMETER;
  }

  FHand = (IMAGE_FILE_HANDLE  *)UserHandle;
  ASSERT (FHand->Signature == IMAGE_FILE_HANDLE_SIGNATURE);

  //
  // Move data from our local copy of the file
  //
  EndPosition = Offset + *ReadSize;
  if (EndPosition > FHand->SourceSize) {
    *ReadSize = (UINT32)(FHand->SourceSize - Offset);
  }
  if (Offset >= FHand->SourceSize) {
      *ReadSize = 0;
  }

  CopyMem (Buffer, (CHAR8 *)FHand->Source + Offset, *ReadSize);
  return EFI_SUCCESS;
}

/**
  Decides whether a PE/COFF image can execute on this system.

  @param[in, out]   Image         LOADED_IMAGE_PRIVATE_DATA struct pointer

  @retval           TRUE          The image is supported
  @retval           FALSE         The image is not supported

**/
STATIC
BOOLEAN
CoreIsImageTypeSupported (
  IN OUT LOADED_IMAGE_PRIVATE_DATA  *Image
  )
{
  return EFI_IMAGE_MACHINE_TYPE_SUPPORTED (Image->ImageContext.Machine) ||
         EFI_IMAGE_MACHINE_CROSS_TYPE_SUPPORTED (Image->ImageContext.Machine);
}

/**
  Loads, relocates, and invokes a PE/COFF image

  @param  BootPolicy              If TRUE, indicates that the request originates
                                  from the boot manager, and that the boot
                                  manager is attempting to load FilePath as a
                                  boot selection.
  @param  Pe32Handle              The handle of PE32 image
  @param  Image                   PE image to be loaded
  @param  DstBuffer               The buffer to store the image
  @param  EntryPoint              A pointer to the entry point
  @param  Attribute               The bit mask of attributes to set for the load
                                  PE image

  @retval EFI_SUCCESS             The file was loaded, relocated, and invoked
  @retval EFI_OUT_OF_RESOURCES    There was not enough memory to load and
                                  relocate the PE/COFF file
  @retval EFI_INVALID_PARAMETER   Invalid parameter
  @retval EFI_BUFFER_TOO_SMALL    Buffer for image is too small

**/
EFI_STATUS
CoreLoadPeImage (
  IN BOOLEAN                     BootPolicy,
  IN VOID                        *Pe32Handle,
  IN LOADED_IMAGE_PRIVATE_DATA   *Image,
  IN EFI_PHYSICAL_ADDRESS        DstBuffer    OPTIONAL,
  OUT EFI_PHYSICAL_ADDRESS       *EntryPoint  OPTIONAL,
  IN  UINT32                     Attribute
  )
{
  EFI_STATUS                Status;
  BOOLEAN                   DstBufAlocated;
  UINTN                     Size;

  ZeroMem (&Image->ImageContext, sizeof (Image->ImageContext));

  Image->ImageContext.Handle    = Pe32Handle;
  Image->ImageContext.ImageRead = (PE_COFF_LOADER_READ_FILE)CoreReadImageFile;

  //
  // Get information about the image being loaded
  //
  Status = PeCoffLoaderGetImageInfo (&Image->ImageContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!CoreIsImageTypeSupported (Image)) {
    //
    // The PE/COFF loader can support loading image types that can be executed.
    // If we loaded an image type that we can not execute return EFI_UNSUPPORTED.
    //
    DEBUG ((DEBUG_ERROR, "Image type %s can't be loaded on %s UEFI system.\n",
      GetMachineTypeName (Image->ImageContext.Machine),
      GetMachineTypeName (mDxeCoreImageMachineType)));
    return EFI_UNSUPPORTED;
  }

  //
  // Set EFI memory type based on ImageType
  //
  switch (Image->ImageContext.ImageType) {
  case EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION:
    Image->ImageContext.ImageCodeMemoryType = EfiLoaderCode;
    Image->ImageContext.ImageDataMemoryType = EfiLoaderData;
    break;
  case EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    Image->ImageContext.ImageCodeMemoryType = EfiBootServicesCode;
    Image->ImageContext.ImageDataMemoryType = EfiBootServicesData;
    break;
  case EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
  case EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:
    Image->ImageContext.ImageCodeMemoryType = EfiRuntimeServicesCode;
    Image->ImageContext.ImageDataMemoryType = EfiRuntimeServicesData;
    break;
  default:
    Image->ImageContext.ImageError = IMAGE_ERROR_INVALID_SUBSYSTEM;
    return EFI_UNSUPPORTED;
  }

  //
  // Allocate memory of the correct memory type aligned on the required image boundary
  //
  DstBufAlocated = FALSE;
  if (DstBuffer == 0) {
    //
    // Allocate Destination Buffer as caller did not pass it in
    //

    if (Image->ImageContext.SectionAlignment > EFI_PAGE_SIZE) {
      Size = (UINTN)Image->ImageContext.ImageSize + Image->ImageContext.SectionAlignment;
    } else {
      Size = (UINTN)Image->ImageContext.ImageSize;
    }

    Image->NumberOfPages = EFI_SIZE_TO_PAGES (Size);

    //
    // If the image relocations have not been stripped, then load at any address.
    // Otherwise load at the address at which it was linked.
    //
    // Memory below 1MB should be treated reserved for CSM and there should be
    // no modules whose preferred load addresses are below 1MB.
    //
    Status = EFI_OUT_OF_RESOURCES;
    //
    // If Loading Module At Fixed Address feature is enabled, the module should be loaded to
    // a specified address.
    //
    {
      if (Image->ImageContext.ImageAddress >= 0x100000 || Image->ImageContext.RelocationsStripped) {
        Status = CoreAllocatePages (
                   AllocateAddress,
                   (EFI_MEMORY_TYPE) (Image->ImageContext.ImageCodeMemoryType),
                   Image->NumberOfPages,
                   &Image->ImageContext.ImageAddress
                   );
      }
      if (EFI_ERROR (Status) && !Image->ImageContext.RelocationsStripped) {
        Status = CoreAllocatePages (
                   AllocateAnyPages,
                   (EFI_MEMORY_TYPE) (Image->ImageContext.ImageCodeMemoryType),
                   Image->NumberOfPages,
                   &Image->ImageContext.ImageAddress
                   );
      }
    }
    if (EFI_ERROR (Status)) {
      return Status;
    }
    DstBufAlocated = TRUE;
  } else {
    //
    // Caller provided the destination buffer
    //

    if (Image->ImageContext.RelocationsStripped && (Image->ImageContext.ImageAddress != DstBuffer)) {
      //
      // If the image relocations were stripped, and the caller provided a
      // destination buffer address that does not match the address that the
      // image is linked at, then the image cannot be loaded.
      //
      return EFI_INVALID_PARAMETER;
    }

    if (Image->NumberOfPages != 0 &&
        Image->NumberOfPages <
        (EFI_SIZE_TO_PAGES ((UINTN)Image->ImageContext.ImageSize + Image->ImageContext.SectionAlignment))) {
      Image->NumberOfPages = EFI_SIZE_TO_PAGES ((UINTN)Image->ImageContext.ImageSize + Image->ImageContext.SectionAlignment);
      return EFI_BUFFER_TOO_SMALL;
    }

    Image->NumberOfPages = EFI_SIZE_TO_PAGES ((UINTN)Image->ImageContext.ImageSize + Image->ImageContext.SectionAlignment);
    Image->ImageContext.ImageAddress = DstBuffer;
  }

  Image->ImageBasePage = Image->ImageContext.ImageAddress;
  if (!Image->ImageContext.IsTeImage) {
    Image->ImageContext.ImageAddress =
        (Image->ImageContext.ImageAddress + Image->ImageContext.SectionAlignment - 1) &
        ~((UINTN)Image->ImageContext.SectionAlignment - 1);
  }

  //
  // Load the image from the file into the allocated memory
  //
  Status = PeCoffLoaderLoadImage (&Image->ImageContext);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // If this is a Runtime Driver, then allocate memory for the FixupData that
  // is used to relocate the image when SetVirtualAddressMap() is called. The
  // relocation is done by the Runtime AP.
  //
  if ((Attribute & EFI_LOAD_PE_IMAGE_ATTRIBUTE_RUNTIME_REGISTRATION) != 0) {
    if (Image->ImageContext.ImageType == EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
      Image->ImageContext.FixupData = AllocateRuntimePool ((UINTN)(Image->ImageContext.FixupDataSize));
      if (Image->ImageContext.FixupData == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto Done;
      }
    }
  }

  //
  // Relocate the image in memory
  //
  Status = PeCoffLoaderRelocateImage (&Image->ImageContext);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // Flush the Instruction Cache
  //
  InvalidateInstructionCacheRange ((VOID *)(UINTN)Image->ImageContext.ImageAddress, (UINTN)Image->ImageContext.ImageSize);

  //
  // Copy the machine type from the context to the image private data.
  //
  Image->Machine = Image->ImageContext.Machine;

  //
  // Get the image entry point.
  //
  Image->EntryPoint   = (EFI_IMAGE_ENTRY_POINT)(UINTN)Image->ImageContext.EntryPoint;

  //
  // Fill in the image information for the Loaded Image Protocol
  //
  Image->Type               = Image->ImageContext.ImageType;
  Image->Info.ImageBase     = (VOID *)(UINTN)Image->ImageContext.ImageAddress;
  Image->Info.ImageSize     = Image->ImageContext.ImageSize;
  Image->Info.ImageCodeType = (EFI_MEMORY_TYPE) (Image->ImageContext.ImageCodeMemoryType);
  Image->Info.ImageDataType = (EFI_MEMORY_TYPE) (Image->ImageContext.ImageDataMemoryType);
  if ((Attribute & EFI_LOAD_PE_IMAGE_ATTRIBUTE_RUNTIME_REGISTRATION) != 0) {
    if (Image->ImageContext.ImageType == EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
      //
      // Make a list off all the RT images so we can let the RT AP know about them.
      //
      Image->RuntimeData = AllocateRuntimePool (sizeof(EFI_RUNTIME_IMAGE_ENTRY));
      if (Image->RuntimeData == NULL) {
        goto Done;
      }
      Image->RuntimeData->ImageBase      = Image->Info.ImageBase;
      Image->RuntimeData->ImageSize      = (UINT64) (Image->Info.ImageSize);
      Image->RuntimeData->RelocationData = Image->ImageContext.FixupData;
      Image->RuntimeData->Handle         = Image->Handle;
      InsertTailList (&gRuntime->ImageHead, &Image->RuntimeData->Link);
    }
  }

  //
  // Fill in the entry point of the image if it is available
  //
  if (EntryPoint != NULL) {
    *EntryPoint = Image->ImageContext.EntryPoint;
  }

  //
  // Print the load address and the PDB file name if it is available
  //

  DEBUG_CODE_BEGIN ();

    UINTN Index;
    UINTN StartIndex;
    CHAR8 EfiFileName[256];


    DEBUG ((DEBUG_INFO | DEBUG_LOAD,
           "Loading driver at 0x%11p EntryPoint=0x%11p ",
           (VOID *)(UINTN) Image->ImageContext.ImageAddress,
           FUNCTION_ENTRY_POINT (Image->ImageContext.EntryPoint)));


    //
    // Print Module Name by Pdb file path.
    // Windows and Unix style file path are all trimmed correctly.
    //
    if (Image->ImageContext.PdbPointer != NULL) {
      StartIndex = 0;
      for (Index = 0; Image->ImageContext.PdbPointer[Index] != 0; Index++) {
        if ((Image->ImageContext.PdbPointer[Index] == '\\') || (Image->ImageContext.PdbPointer[Index] == '/')) {
          StartIndex = Index + 1;
        }
      }
      //
      // Copy the PDB file name to our temporary string, and replace .pdb with .efi
      // The PDB file name is limited in the range of 0~255.
      // If the length is bigger than 255, trim the redudant characters to avoid overflow in array boundary.
      //
      for (Index = 0; Index < sizeof (EfiFileName) - 4; Index++) {
        EfiFileName[Index] = Image->ImageContext.PdbPointer[Index + StartIndex];
        if (EfiFileName[Index] == 0) {
          EfiFileName[Index] = '.';
        }
        if (EfiFileName[Index] == '.') {
          EfiFileName[Index + 1] = 'e';
          EfiFileName[Index + 2] = 'f';
          EfiFileName[Index + 3] = 'i';
          EfiFileName[Index + 4] = 0;
          break;
        }
      }

      if (Index == sizeof (EfiFileName) - 4) {
        EfiFileName[Index] = 0;
      }
      DEBUG ((DEBUG_INFO | DEBUG_LOAD, "%a", EfiFileName)); // &Image->ImageContext.PdbPointer[StartIndex]));
    }
    DEBUG ((DEBUG_INFO | DEBUG_LOAD, "\n"));

  DEBUG_CODE_END ();

  return EFI_SUCCESS;

Done:

  //
  // Free memory.
  //

  if (DstBufAlocated) {
    CoreFreePages (Image->ImageContext.ImageAddress, Image->NumberOfPages);
    Image->ImageContext.ImageAddress = 0;
    Image->ImageBasePage = 0;
  }

  if (Image->ImageContext.FixupData != NULL) {
    CoreFreePool (Image->ImageContext.FixupData);
  }

  return Status;
}



/**
  Get the image's private data from its handle.

  @param  ImageHandle             The image handle

  @return Return the image private data associated with ImageHandle.

**/
LOADED_IMAGE_PRIVATE_DATA *
CoreLoadedImageInfo (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                 Status;
  EFI_LOADED_IMAGE_PROTOCOL  *LoadedImage;
  LOADED_IMAGE_PRIVATE_DATA  *Image;

  Status = CoreHandleProtocol (
             ImageHandle,
             &gEfiLoadedImageProtocolGuid,
             (VOID **)&LoadedImage
             );
  if (!EFI_ERROR (Status)) {
    Image = LOADED_IMAGE_PRIVATE_DATA_FROM_THIS (LoadedImage);
  } else {
    DEBUG ((DEBUG_LOAD, "CoreLoadedImageInfo: Not an ImageHandle %p\n", ImageHandle));
    Image = NULL;
  }

  return Image;
}


/**
  Unloads EFI image from memory.

  @param  Image                   EFI image
  @param  FreePage                Free allocated pages

**/
VOID
CoreUnloadAndCloseImage (
  IN LOADED_IMAGE_PRIVATE_DATA  *Image,
  IN BOOLEAN                    FreePage
  )
{
  EFI_STATUS                          Status;
  UINTN                               HandleCount;
  EFI_HANDLE                          *HandleBuffer;
  UINTN                               HandleIndex;
  EFI_GUID                            **ProtocolGuidArray;
  UINTN                               ArrayCount;
  UINTN                               ProtocolIndex;
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *OpenInfo;
  UINTN                               OpenInfoCount;
  UINTN                               OpenInfoIndex;

  HandleBuffer = NULL;
  ProtocolGuidArray = NULL;

  //
  // Unload image, free Image->ImageContext->ModHandle
  //
  PeCoffLoaderUnloadImage (&Image->ImageContext);

  //
  // Free our references to the image handle
  //
  if (Image->Handle != NULL) {

    Status = CoreLocateHandleBuffer (
               AllHandles,
               NULL,
               NULL,
               &HandleCount,
               &HandleBuffer
               );
    if (!EFI_ERROR (Status)) {
      for (HandleIndex = 0; HandleIndex < HandleCount; HandleIndex++) {
        Status = CoreProtocolsPerHandle (
                   HandleBuffer[HandleIndex],
                   &ProtocolGuidArray,
                   &ArrayCount
                   );
        if (!EFI_ERROR (Status)) {
          for (ProtocolIndex = 0; ProtocolIndex < ArrayCount; ProtocolIndex++) {
            Status = CoreOpenProtocolInformation (
                       HandleBuffer[HandleIndex],
                       ProtocolGuidArray[ProtocolIndex],
                       &OpenInfo,
                       &OpenInfoCount
                       );
            if (!EFI_ERROR (Status)) {
              for (OpenInfoIndex = 0; OpenInfoIndex < OpenInfoCount; OpenInfoIndex++) {
                if (OpenInfo[OpenInfoIndex].AgentHandle == Image->Handle) {
                  Status = CoreCloseProtocol (
                             HandleBuffer[HandleIndex],
                             ProtocolGuidArray[ProtocolIndex],
                             Image->Handle,
                             OpenInfo[OpenInfoIndex].ControllerHandle
                             );
                }
              }
              if (OpenInfo != NULL) {
                CoreFreePool(OpenInfo);
              }
            }
          }
          if (ProtocolGuidArray != NULL) {
            CoreFreePool(ProtocolGuidArray);
          }
        }
      }
      if (HandleBuffer != NULL) {
        CoreFreePool (HandleBuffer);
      }
    }

    Status = CoreUninstallProtocolInterface (
               Image->Handle,
               &gEfiLoadedImageDevicePathProtocolGuid,
               Image->LoadedImageDevicePath
               );

    Status = CoreUninstallProtocolInterface (
               Image->Handle,
               &gEfiLoadedImageProtocolGuid,
               &Image->Info
               );

  }

  if (Image->RuntimeData != NULL) {
    if (Image->RuntimeData->Link.ForwardLink != NULL) {
      //
      // Remove the Image from the Runtime Image list as we are about to Free it!
      //
      RemoveEntryList (&Image->RuntimeData->Link);
    }
    CoreFreePool (Image->RuntimeData);
  }

  //
  // Free the Image from memory
  //
  if ((Image->ImageBasePage != 0) && FreePage) {
    CoreFreePages (Image->ImageBasePage, Image->NumberOfPages);
  }

  //
  // Done with the Image structure
  //
  if (Image->Info.FilePath != NULL) {
    CoreFreePool (Image->Info.FilePath);
  }

  if (Image->LoadedImageDevicePath != NULL) {
    CoreFreePool (Image->LoadedImageDevicePath);
  }

  if (Image->FixupData != NULL) {
    CoreFreePool (Image->FixupData);
  }

  CoreFreePool (Image);
}

/**
  Get the image file buffer data and buffer size by its device path.

  Access the file either from a firmware volume, from a file system interface,
  or from the load file interface.

  Allocate memory to store the found image. The caller is responsible to free memory.

  If FilePath is NULL, then NULL is returned.
  If FileSize is NULL, then NULL is returned.
  If AuthenticationStatus is NULL, then NULL is returned.

  @param[in]       BootPolicy           Policy for Open Image File.If TRUE, indicates
                                        that the request originates from the boot
                                        manager, and that the boot manager is
                                        attempting to load FilePath as a boot
                                        selection. If FALSE, then FilePath must
                                        match an exact file to be loaded.
  @param[in]       FilePath             The pointer to the device path of the file
                                        that is absracted to the file buffer.
  @param[out]      FileSize             The pointer to the size of the abstracted
                                        file buffer.
  @param[out]      AuthenticationStatus Pointer to the authentication status.

  @retval NULL   FilePath is NULL, or FileSize is NULL, or AuthenticationStatus is NULL, or the file can't be found.
  @retval other  The abstracted file buffer. The caller is responsible to free memory.
**/
VOID *
EFIAPI
GetFileBufferByFilePath (
  IN BOOLEAN                           BootPolicy,
  IN CONST EFI_DEVICE_PATH_PROTOCOL    *FilePath,
  OUT      UINTN                       *FileSize,
  OUT UINT32                           *AuthenticationStatus
  )
{
  EFI_DEVICE_PATH_PROTOCOL          *DevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL          *OrigDevicePathNode;
  EFI_DEVICE_PATH_PROTOCOL          *TempDevicePathNode;
  EFI_HANDLE                        Handle;
  UINT8                             *ImageBuffer;
  UINTN                             ImageBufferSize;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL   *Volume;
  EFI_FILE_HANDLE                   FileHandle;
  EFI_FILE_HANDLE                   LastHandle;
  EFI_FILE_INFO                     *FileInfo;
  UINTN                             FileInfoSize;
  EFI_LOAD_FILE_PROTOCOL            *LoadFile;
  EFI_LOAD_FILE2_PROTOCOL           *LoadFile2;
  EFI_STATUS                        Status;

  //
  // Check input File device path.
  //
  if (FilePath == NULL || FileSize == NULL || AuthenticationStatus == NULL) {
    return NULL;
  }

  //
  // Init local variable
  //
  TempDevicePathNode  = NULL;
  FileInfo            = NULL;
  FileHandle          = NULL;
  ImageBuffer         = NULL;
  ImageBufferSize     = 0;
  *AuthenticationStatus = 0;

  //
  // Copy File Device Path
  //
  OrigDevicePathNode = DuplicateDevicePath (FilePath);
  if (OrigDevicePathNode == NULL) {
    return NULL;
  }

  //
  // Attempt to access the file via a file system interface
  //
  DevicePathNode = OrigDevicePathNode;
  Status = gBS->LocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &DevicePathNode, &Handle);
  if (!EFI_ERROR (Status)) {
    Status = gBS->HandleProtocol (Handle, &gEfiSimpleFileSystemProtocolGuid, (VOID**)&Volume);
    if (!EFI_ERROR (Status)) {
      //
      // Open the Volume to get the File System handle
      //
      Status = Volume->OpenVolume (Volume, &FileHandle);
      if (!EFI_ERROR (Status)) {
        //
        // Duplicate the device path to avoid the access to unaligned device path node.
        // Because the device path consists of one or more FILE PATH MEDIA DEVICE PATH
        // nodes, It assures the fields in device path nodes are 2 byte aligned.
        //
        TempDevicePathNode = DuplicateDevicePath (DevicePathNode);
        if (TempDevicePathNode == NULL) {
          FileHandle->Close (FileHandle);
          //
          // Setting Status to an EFI_ERROR value will cause the rest of
          // the file system support below to be skipped.
          //
          Status = EFI_OUT_OF_RESOURCES;
        }
        //
        // Parse each MEDIA_FILEPATH_DP node. There may be more than one, since the
        // directory information and filename can be seperate. The goal is to inch
        // our way down each device path node and close the previous node
        //
        DevicePathNode = TempDevicePathNode;
        while (!EFI_ERROR (Status) && !IsDevicePathEnd (DevicePathNode)) {
          if (DevicePathType (DevicePathNode) != MEDIA_DEVICE_PATH ||
              DevicePathSubType (DevicePathNode) != MEDIA_FILEPATH_DP) {
            Status = EFI_UNSUPPORTED;
            break;
          }

          LastHandle = FileHandle;
          FileHandle = NULL;

          Status = LastHandle->Open (
                                LastHandle,
                                &FileHandle,
                                ((FILEPATH_DEVICE_PATH *) DevicePathNode)->PathName,
                                EFI_FILE_MODE_READ,
                                0
                                );

          //
          // Close the previous node
          //
          LastHandle->Close (LastHandle);

          DevicePathNode = NextDevicePathNode (DevicePathNode);
        }

        if (!EFI_ERROR (Status)) {
          //
          // We have found the file. Now we need to read it. Before we can read the file we need to
          // figure out how big the file is.
          //
          FileInfo = NULL;
          FileInfoSize = 0;
          Status = FileHandle->GetInfo (
                                FileHandle,
                                &gEfiFileInfoGuid,
                                &FileInfoSize,
                                FileInfo
                                );

          if (Status == EFI_BUFFER_TOO_SMALL) {
            FileInfo = AllocatePool (FileInfoSize);
            if (FileInfo == NULL) {
              Status = EFI_OUT_OF_RESOURCES;
            } else {
              Status = FileHandle->GetInfo (
                                    FileHandle,
                                    &gEfiFileInfoGuid,
                                    &FileInfoSize,
                                    FileInfo
                                    );
            }
          }

          if (!EFI_ERROR (Status) && (FileInfo != NULL)) {
            if ((FileInfo->Attribute & EFI_FILE_DIRECTORY) == 0) {
              //
              // Allocate space for the file
              //
              ImageBuffer = AllocatePool ((UINTN)FileInfo->FileSize);
              if (ImageBuffer == NULL) {
                Status = EFI_OUT_OF_RESOURCES;
              } else {
                //
                // Read the file into the buffer we allocated
                //
                ImageBufferSize = (UINTN)FileInfo->FileSize;
                Status          = FileHandle->Read (FileHandle, &ImageBufferSize, ImageBuffer);
              }
            }
          }
        }
        //
        // Close the file and Free FileInfo and TempDevicePathNode since we are done
        //
        if (FileInfo != NULL) {
          FreePool (FileInfo);
        }
        if (FileHandle != NULL) {
          FileHandle->Close (FileHandle);
        }
        if (TempDevicePathNode != NULL) {
          FreePool (TempDevicePathNode);
        }
      }
    }
    if (!EFI_ERROR (Status)) {
      goto Finish;
    }
  }

  //
  // Attempt to access the file via LoadFile2 interface
  //
  if (!BootPolicy) {
    DevicePathNode = OrigDevicePathNode;
    Status = gBS->LocateDevicePath (&gEfiLoadFile2ProtocolGuid, &DevicePathNode, &Handle);
    if (!EFI_ERROR (Status)) {
      Status = gBS->HandleProtocol (Handle, &gEfiLoadFile2ProtocolGuid, (VOID**)&LoadFile2);
      if (!EFI_ERROR (Status)) {
        //
        // Call LoadFile2 with the correct buffer size
        //
        ImageBufferSize = 0;
        ImageBuffer     = NULL;
        Status = LoadFile2->LoadFile (
                             LoadFile2,
                             DevicePathNode,
                             FALSE,
                             &ImageBufferSize,
                             ImageBuffer
                             );
        if (Status == EFI_BUFFER_TOO_SMALL) {
          ImageBuffer = AllocatePool (ImageBufferSize);
          if (ImageBuffer == NULL) {
            Status = EFI_OUT_OF_RESOURCES;
          } else {
            Status = LoadFile2->LoadFile (
                                 LoadFile2,
                                 DevicePathNode,
                                 FALSE,
                                 &ImageBufferSize,
                                 ImageBuffer
                                 );
          }
        }
      }
      if (!EFI_ERROR (Status)) {
        goto Finish;
      }
    }
  }

  //
  // Attempt to access the file via LoadFile interface
  //
  DevicePathNode = OrigDevicePathNode;
  Status = gBS->LocateDevicePath (&gEfiLoadFileProtocolGuid, &DevicePathNode, &Handle);
  if (!EFI_ERROR (Status)) {
    Status = gBS->HandleProtocol (Handle, &gEfiLoadFileProtocolGuid, (VOID**)&LoadFile);
    if (!EFI_ERROR (Status)) {
      //
      // Call LoadFile with the correct buffer size
      //
      ImageBufferSize = 0;
      ImageBuffer     = NULL;
      Status = LoadFile->LoadFile (
                           LoadFile,
                           DevicePathNode,
                           BootPolicy,
                           &ImageBufferSize,
                           ImageBuffer
                           );
      if (Status == EFI_BUFFER_TOO_SMALL) {
        ImageBuffer = AllocatePool (ImageBufferSize);
        if (ImageBuffer == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
        } else {
          Status = LoadFile->LoadFile (
                               LoadFile,
                               DevicePathNode,
                               BootPolicy,
                               &ImageBufferSize,
                               ImageBuffer
                               );
        }
      }
    }
  }

Finish:

  if (EFI_ERROR (Status)) {
    if (ImageBuffer != NULL) {
      FreePool (ImageBuffer);
      ImageBuffer = NULL;
    }
    *FileSize = 0;
  } else {
    *FileSize = ImageBufferSize;
  }

  FreePool (OrigDevicePathNode);

  return ImageBuffer;
}


/**
  Loads an EFI image into memory and returns a handle to the image.

  @param  BootPolicy              If TRUE, indicates that the request originates
                                  from the boot manager, and that the boot
                                  manager is attempting to load FilePath as a
                                  boot selection.
  @param  ParentImageHandle       The caller's image handle.
  @param  FilePath                The specific file path from which the image is
                                  loaded.
  @param  SourceBuffer            If not NULL, a pointer to the memory location
                                  containing a copy of the image to be loaded.
  @param  SourceSize              The size in bytes of SourceBuffer.
  @param  DstBuffer               The buffer to store the image
  @param  NumberOfPages           If not NULL, it inputs a pointer to the page
                                  number of DstBuffer and outputs a pointer to
                                  the page number of the image. If this number is
                                  not enough,  return EFI_BUFFER_TOO_SMALL and
                                  this parameter contains the required number.
  @param  ImageHandle             Pointer to the returned image handle that is
                                  created when the image is successfully loaded.
  @param  EntryPoint              A pointer to the entry point
  @param  Attribute               The bit mask of attributes to set for the load
                                  PE image

  @retval EFI_SUCCESS             The image was loaded into memory.
  @retval EFI_NOT_FOUND           The FilePath was not found.
  @retval EFI_INVALID_PARAMETER   One of the parameters has an invalid value.
  @retval EFI_BUFFER_TOO_SMALL    The buffer is too small
  @retval EFI_UNSUPPORTED         The image type is not supported, or the device
                                  path cannot be parsed to locate the proper
                                  protocol for loading the file.
  @retval EFI_OUT_OF_RESOURCES    Image was not loaded due to insufficient
                                  resources.
  @retval EFI_LOAD_ERROR          Image was not loaded because the image format was corrupt or not
                                  understood.
  @retval EFI_DEVICE_ERROR        Image was not loaded because the device returned a read error.
  @retval EFI_ACCESS_DENIED       Image was not loaded because the platform policy prohibits the
                                  image from being loaded. NULL is returned in *ImageHandle.
  @retval EFI_SECURITY_VIOLATION  Image was loaded and an ImageHandle was created with a
                                  valid EFI_LOADED_IMAGE_PROTOCOL. However, the current
                                  platform policy specifies that the image should not be started.

**/
EFI_STATUS
CoreLoadImageCommon (
  IN  BOOLEAN                          BootPolicy,
  IN  EFI_HANDLE                       ParentImageHandle,
  IN  EFI_DEVICE_PATH_PROTOCOL         *FilePath,
  IN  VOID                             *SourceBuffer       OPTIONAL,
  IN  UINTN                            SourceSize,
  IN  EFI_PHYSICAL_ADDRESS             DstBuffer           OPTIONAL,
  IN OUT UINTN                         *NumberOfPages      OPTIONAL,
  OUT EFI_HANDLE                       *ImageHandle,
  OUT EFI_PHYSICAL_ADDRESS             *EntryPoint         OPTIONAL,
  IN  UINT32                           Attribute
  )
{
  LOADED_IMAGE_PRIVATE_DATA  *Image;
  LOADED_IMAGE_PRIVATE_DATA  *ParentImage;
  IMAGE_FILE_HANDLE          FHand;
  EFI_STATUS                 Status;
  EFI_STATUS                 SecurityStatus;
  EFI_HANDLE                 DeviceHandle;
  UINT32                     AuthenticationStatus;
  EFI_DEVICE_PATH_PROTOCOL   *OriginalFilePath;
  EFI_DEVICE_PATH_PROTOCOL   *HandleFilePath;
  EFI_DEVICE_PATH_PROTOCOL   *InputFilePath;
  EFI_DEVICE_PATH_PROTOCOL   *Node;
  UINTN                      FilePathSize;
  BOOLEAN                    ImageIsFromLoadFile;

  SecurityStatus = EFI_SUCCESS;

  ASSERT (gEfiCurrentTpl < TPL_NOTIFY);
  ParentImage = NULL;

  //
  // The caller must pass in a valid ParentImageHandle
  //
  if (ImageHandle == NULL || ParentImageHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ParentImage = CoreLoadedImageInfo (ParentImageHandle);
  if (ParentImage == NULL) {
    DEBUG((DEBUG_LOAD|DEBUG_ERROR, "LoadImageEx: Parent handle not an image handle\n"));
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&FHand, sizeof (IMAGE_FILE_HANDLE));
  FHand.Signature  = IMAGE_FILE_HANDLE_SIGNATURE;
  OriginalFilePath = FilePath;
  InputFilePath    = FilePath;
  HandleFilePath   = FilePath;
  DeviceHandle     = NULL;
  Status           = EFI_SUCCESS;
  AuthenticationStatus = 0;
  ImageIsFromLoadFile  = FALSE;

  //
  // If the caller passed a copy of the file, then just use it
  //
  if (SourceBuffer != NULL) {
    FHand.Source     = SourceBuffer;
    FHand.SourceSize = SourceSize;
    Status = CoreLocateDevicePath (&gEfiDevicePathProtocolGuid, &HandleFilePath, &DeviceHandle);
    if (EFI_ERROR (Status)) {
      DeviceHandle = NULL;
    }
    if (SourceSize > 0) {
      Status = EFI_SUCCESS;
    } else {
      Status = EFI_LOAD_ERROR;
    }
  } else {
    if (FilePath == NULL) {
      return EFI_INVALID_PARAMETER;
    }

    //
    // Try to get the image device handle by checking the match protocol.
    //
    Node   = NULL;
    {
      HandleFilePath = FilePath;
      Status = CoreLocateDevicePath (&gEfiSimpleFileSystemProtocolGuid, &HandleFilePath, &DeviceHandle);
      if (EFI_ERROR (Status)) {
        if (!BootPolicy) {
          HandleFilePath = FilePath;
          Status = CoreLocateDevicePath (&gEfiLoadFile2ProtocolGuid, &HandleFilePath, &DeviceHandle);
        }
        if (EFI_ERROR (Status)) {
          HandleFilePath = FilePath;
          Status = CoreLocateDevicePath (&gEfiLoadFileProtocolGuid, &HandleFilePath, &DeviceHandle);
          if (!EFI_ERROR (Status)) {
            ImageIsFromLoadFile = TRUE;
            Node = HandleFilePath;
          }
        }
      }
    }

    //
    // Get the source file buffer by its device path.
    //
    FHand.Source = GetFileBufferByFilePath (
                      BootPolicy,
                      FilePath,
                      &FHand.SourceSize,
                      &AuthenticationStatus
                      );
    if (FHand.Source == NULL) {
      Status = EFI_NOT_FOUND;
    } else {
      FHand.FreeBuffer = TRUE;
      if (ImageIsFromLoadFile) {
        //
        // LoadFile () may cause the device path of the Handle be updated.
        //
        OriginalFilePath = AppendDevicePath (DevicePathFromHandle (DeviceHandle), Node);
      }
    }
  }

  if (EFI_ERROR (Status)) {
    Image = NULL;
    goto Done;
  }

  if (gSecurity2 != NULL) {
    //
    // Verify File Authentication through the Security2 Architectural Protocol
    //
    SecurityStatus = gSecurity2->FileAuthentication (
                                  gSecurity2,
                                  OriginalFilePath,
                                  FHand.Source,
                                  FHand.SourceSize,
                                  BootPolicy
                                  );
    if (!EFI_ERROR (SecurityStatus)) {
      //
      // When Security2 is installed, Security Architectural Protocol must be published.
      //
      ASSERT (gSecurity != NULL);

      //
      // Verify the Authentication Status through the Security Architectural Protocol
      // Only on images that have been read using Firmware Volume protocol.
      //
      SecurityStatus = gSecurity->FileAuthenticationState (
                                    gSecurity,
                                    AuthenticationStatus,
                                    OriginalFilePath
                                    );
    }
  } else if ((gSecurity != NULL) && (OriginalFilePath != NULL)) {
    //
    // Verify the Authentication Status through the Security Architectural Protocol
    //
    SecurityStatus = gSecurity->FileAuthenticationState (
                                  gSecurity,
                                  AuthenticationStatus,
                                  OriginalFilePath
                                  );
  }

  //
  // Check Security Status.
  //
  if (EFI_ERROR (SecurityStatus) && SecurityStatus != EFI_SECURITY_VIOLATION) {
    if (SecurityStatus == EFI_ACCESS_DENIED) {
      //
      // Image was not loaded because the platform policy prohibits the image from being loaded.
      // It's the only place we could meet EFI_ACCESS_DENIED.
      //
      *ImageHandle = NULL;
    }
    Status = SecurityStatus;
    Image = NULL;
    goto Done;
  }

  //
  // Allocate a new image structure
  //
  Image = AllocateZeroPool (sizeof(LOADED_IMAGE_PRIVATE_DATA));
  if (Image == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  //
  // Pull out just the file portion of the DevicePath for the LoadedImage FilePath
  //
  FilePath = OriginalFilePath;
  if (DeviceHandle != NULL) {
    Status = CoreHandleProtocol (DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID **)&HandleFilePath);
    if (!EFI_ERROR (Status)) {
      FilePathSize = GetDevicePathSize (HandleFilePath) - sizeof(EFI_DEVICE_PATH_PROTOCOL);
      FilePath = (EFI_DEVICE_PATH_PROTOCOL *) (((UINT8 *)FilePath) + FilePathSize );
    }
  }
  //
  // Initialize the fields for an internal driver
  //
  Image->Signature         = LOADED_IMAGE_PRIVATE_DATA_SIGNATURE;
  Image->Info.SystemTable  = gDxeCoreST;
  Image->Info.DeviceHandle = DeviceHandle;
  Image->Info.Revision     = EFI_LOADED_IMAGE_PROTOCOL_REVISION;
  Image->Info.FilePath     = DuplicateDevicePath (FilePath);
  Image->Info.ParentHandle = ParentImageHandle;


  if (NumberOfPages != NULL) {
    Image->NumberOfPages = *NumberOfPages ;
  } else {
    Image->NumberOfPages = 0 ;
  }

  //
  // Install the protocol interfaces for this image
  // don't fire notifications yet
  //
  Status = CoreInstallProtocolInterfaceNotify (
             &Image->Handle,
             &gEfiLoadedImageProtocolGuid,
             EFI_NATIVE_INTERFACE,
             &Image->Info,
             FALSE
             );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // Load the image.  If EntryPoint is Null, it will not be set.
  //
  Status = CoreLoadPeImage (BootPolicy, &FHand, Image, DstBuffer, EntryPoint, Attribute);
  if (EFI_ERROR (Status)) {
    if ((Status == EFI_BUFFER_TOO_SMALL) || (Status == EFI_OUT_OF_RESOURCES)) {
      if (NumberOfPages != NULL) {
        *NumberOfPages = Image->NumberOfPages;
      }
    }
    goto Done;
  }

  if (NumberOfPages != NULL) {
    *NumberOfPages = Image->NumberOfPages;
  }

  //
  //Reinstall loaded image protocol to fire any notifications
  //
  Status = CoreReinstallProtocolInterface (
             Image->Handle,
             &gEfiLoadedImageProtocolGuid,
             &Image->Info,
             &Image->Info
             );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // If DevicePath parameter to the LoadImage() is not NULL, then make a copy of DevicePath,
  // otherwise Loaded Image Device Path Protocol is installed with a NULL interface pointer.
  //
  if (OriginalFilePath != NULL) {
    Image->LoadedImageDevicePath = DuplicateDevicePath (OriginalFilePath);
  }

  //
  // Install Loaded Image Device Path Protocol onto the image handle of a PE/COFE image
  //
  Status = CoreInstallProtocolInterface (
            &Image->Handle,
            &gEfiLoadedImageDevicePathProtocolGuid,
            EFI_NATIVE_INTERFACE,
            Image->LoadedImageDevicePath
            );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  //
  // Success.  Return the image handle
  //
  *ImageHandle = Image->Handle;

Done:
  //
  // All done accessing the source file
  // If we allocated the Source buffer, free it
  //
  if (FHand.FreeBuffer) {
    CoreFreePool (FHand.Source);
  }
  if (OriginalFilePath != InputFilePath) {
    CoreFreePool (OriginalFilePath);
  }

  //
  // There was an error.  If there's an Image structure, free it
  //
  if (EFI_ERROR (Status)) {
    if (Image != NULL) {
      CoreUnloadAndCloseImage (Image, (BOOLEAN)(DstBuffer == 0));
      Image = NULL;
    }
  } else if (EFI_ERROR (SecurityStatus)) {
    Status = SecurityStatus;
  }

  //
  // Track the return status from LoadImage.
  //
  if (Image != NULL) {
    Image->LoadImageStatus = Status;
  }

  return Status;
}




/**
  Loads an EFI image into memory and returns a handle to the image.

  @param  BootPolicy              If TRUE, indicates that the request originates
                                  from the boot manager, and that the boot
                                  manager is attempting to load FilePath as a
                                  boot selection.
  @param  ParentImageHandle       The caller's image handle.
  @param  FilePath                The specific file path from which the image is
                                  loaded.
  @param  SourceBuffer            If not NULL, a pointer to the memory location
                                  containing a copy of the image to be loaded.
  @param  SourceSize              The size in bytes of SourceBuffer.
  @param  ImageHandle             Pointer to the returned image handle that is
                                  created when the image is successfully loaded.

  @retval EFI_SUCCESS             The image was loaded into memory.
  @retval EFI_NOT_FOUND           The FilePath was not found.
  @retval EFI_INVALID_PARAMETER   One of the parameters has an invalid value.
  @retval EFI_UNSUPPORTED         The image type is not supported, or the device
                                  path cannot be parsed to locate the proper
                                  protocol for loading the file.
  @retval EFI_OUT_OF_RESOURCES    Image was not loaded due to insufficient
                                  resources.
  @retval EFI_LOAD_ERROR          Image was not loaded because the image format was corrupt or not
                                  understood.
  @retval EFI_DEVICE_ERROR        Image was not loaded because the device returned a read error.
  @retval EFI_ACCESS_DENIED       Image was not loaded because the platform policy prohibits the
                                  image from being loaded. NULL is returned in *ImageHandle.
  @retval EFI_SECURITY_VIOLATION  Image was loaded and an ImageHandle was created with a
                                  valid EFI_LOADED_IMAGE_PROTOCOL. However, the current
                                  platform policy specifies that the image should not be started.

**/
EFI_STATUS
EFIAPI
CoreLoadImage (
  IN BOOLEAN                    BootPolicy,
  IN EFI_HANDLE                 ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL   *FilePath,
  IN VOID                       *SourceBuffer   OPTIONAL,
  IN UINTN                      SourceSize,
  OUT EFI_HANDLE                *ImageHandle
  )
{
  EFI_STATUS    Status;
  EFI_HANDLE    Handle;

  Status = CoreLoadImageCommon (
             BootPolicy,
             ParentImageHandle,
             FilePath,
             SourceBuffer,
             SourceSize,
             (EFI_PHYSICAL_ADDRESS) (UINTN) NULL,
             NULL,
             ImageHandle,
             NULL,
             EFI_LOAD_PE_IMAGE_ATTRIBUTE_RUNTIME_REGISTRATION | EFI_LOAD_PE_IMAGE_ATTRIBUTE_DEBUG_IMAGE_INFO_TABLE_REGISTRATION
             );

  Handle = NULL;
  if (!EFI_ERROR (Status)) {
    //
    // ImageHandle will be valid only Status is success.
    //
    Handle = *ImageHandle;
  }

  return Status;
}

/**
  Transfer control to a loaded image's entry point.

  @param  ImageHandle             Handle of image to be started.
  @param  ExitDataSize            Pointer of the size to ExitData
  @param  ExitData                Pointer to a pointer to a data buffer that
                                  includes a Null-terminated string,
                                  optionally followed by additional binary data.
                                  The string is a description that the caller may
                                  use to further indicate the reason for the
                                  image's exit.

  @retval EFI_INVALID_PARAMETER   Invalid parameter
  @retval EFI_OUT_OF_RESOURCES    No enough buffer to allocate
  @retval EFI_SECURITY_VIOLATION  The current platform policy specifies that the image should not be started.
  @retval EFI_SUCCESS             Successfully transfer control to the image's
                                  entry point.

**/
EFI_STATUS
EFIAPI
CoreStartImage (
  IN EFI_HANDLE  ImageHandle,
  OUT UINTN      *ExitDataSize,
  OUT CHAR16     **ExitData  OPTIONAL
  )
{
  EFI_STATUS                    Status;
  LOADED_IMAGE_PRIVATE_DATA     *Image;
  LOADED_IMAGE_PRIVATE_DATA     *LastImage;
  UINT64                        HandleDatabaseKey;
  UINTN                         SetJumpFlag;
  EFI_HANDLE                    Handle;

  Handle = ImageHandle;

  Image = CoreLoadedImageInfo (ImageHandle);
  if (Image == NULL  ||  Image->Started) {
    return EFI_INVALID_PARAMETER;
  }
  if (EFI_ERROR (Image->LoadImageStatus)) {
    return Image->LoadImageStatus;
  }

  //
  // The image to be started must have the machine type supported by DxeCore.
  //
  if (!EFI_IMAGE_MACHINE_TYPE_SUPPORTED (Image->Machine)) {
    //
    // Do not ASSERT here, because image might be loaded via EFI_IMAGE_MACHINE_CROSS_TYPE_SUPPORTED
    // But it can not be started.
    //
    DEBUG ((EFI_D_ERROR, "Image type %s can't be started ", GetMachineTypeName(Image->Machine)));
    DEBUG ((EFI_D_ERROR, "on %s UEFI system.\n", GetMachineTypeName(mDxeCoreImageMachineType)));
    return EFI_UNSUPPORTED;
  }

  //
  // Push the current start image context, and
  // link the current image to the head.   This is the
  // only image that can call Exit()
  //
  HandleDatabaseKey = CoreGetHandleDatabaseKey ();
  LastImage         = mCurrentImage;
  mCurrentImage     = Image;
  Image->Tpl        = gEfiCurrentTpl;

  //
  // Set long jump for Exit() support
  // JumpContext must be aligned on a CPU specific boundary.
  // Overallocate the buffer and force the required alignment
  //
  Image->JumpBuffer = AllocatePool (sizeof (BASE_LIBRARY_JUMP_BUFFER) + BASE_LIBRARY_JUMP_BUFFER_ALIGNMENT);
  if (Image->JumpBuffer == NULL) {
    //
    // Pop the current start image context
    //
    mCurrentImage = LastImage;

    return EFI_OUT_OF_RESOURCES;
  }
  Image->JumpContext = ALIGN_POINTER (Image->JumpBuffer, BASE_LIBRARY_JUMP_BUFFER_ALIGNMENT);

  SetJumpFlag = SetJump (Image->JumpContext);
  //
  // The initial call to SetJump() must always return 0.
  // Subsequent calls to LongJump() cause a non-zero value to be returned by SetJump().
  //
  if (SetJumpFlag == 0) {
    //
    // Call the image's entry point
    //
    Image->Started = TRUE;
    Image->Status = Image->EntryPoint (ImageHandle, Image->Info.SystemTable);

    //
    // Add some debug information if the image returned with error.
    // This make the user aware and check if the driver image have already released
    // all the resource in this situation.
    //
    DEBUG_CODE_BEGIN ();
      if (EFI_ERROR (Image->Status)) {
        DEBUG ((DEBUG_ERROR, "Error: Image at %11p start failed: %r\n", Image->Info.ImageBase, Image->Status));
      }
    DEBUG_CODE_END ();

    //
    // If the image returns, exit it through Exit()
    //
    CoreExit (ImageHandle, Image->Status, 0, NULL);
  }

  //
  // Image has completed.  Verify the tpl is the same
  //
  ASSERT (Image->Tpl == gEfiCurrentTpl);
  CoreRestoreTpl (Image->Tpl);

  CoreFreePool (Image->JumpBuffer);

  //
  // Pop the current start image context
  //
  mCurrentImage = LastImage;

  //
  // UEFI Specification - StartImage() - EFI 1.10 Extension
  // To maintain compatibility with UEFI drivers that are written to the EFI
  // 1.02 Specification, StartImage() must monitor the handle database before
  // and after each image is started. If any handles are created or modified
  // when an image is started, then EFI_BOOT_SERVICES.ConnectController() must
  // be called with the Recursive parameter set to TRUE for each of the newly
  // created or modified handles before StartImage() returns.
  //
  if (Image->Type != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) {
    CoreConnectHandlesByKey (HandleDatabaseKey);
  }

  //
  // Handle the image's returned ExitData
  //
  DEBUG_CODE_BEGIN ();
    if (Image->ExitDataSize != 0 || Image->ExitData != NULL) {

      DEBUG ((DEBUG_LOAD, "StartImage: ExitDataSize %d, ExitData %p", (UINT32)Image->ExitDataSize, Image->ExitData));
      if (Image->ExitData != NULL) {
        DEBUG ((DEBUG_LOAD, " (%hs)", Image->ExitData));
      }
      DEBUG ((DEBUG_LOAD, "\n"));
    }
  DEBUG_CODE_END ();

  //
  //  Return the exit data to the caller
  //
  if (ExitData != NULL && ExitDataSize != NULL) {
    *ExitDataSize = Image->ExitDataSize;
    *ExitData     = Image->ExitData;
  } else {
    //
    // Caller doesn't want the exit data, free it
    //
    CoreFreePool (Image->ExitData);
    Image->ExitData = NULL;
  }

  //
  // Save the Status because Image will get destroyed if it is unloaded.
  //
  Status = Image->Status;

  //
  // If the image returned an error, or if the image is an application
  // unload it
  //
  if (EFI_ERROR (Image->Status) || Image->Type == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION) {
    CoreUnloadAndCloseImage (Image, TRUE);
    //
    // ImageHandle may be invalid after the image is unloaded, so use NULL handle to record perf log.
    //
    Handle = NULL;
  }

  //
  // Done
  //
  return Status;
}

/**
  Terminates the currently loaded EFI image and returns control to boot services.

  @param  ImageHandle             Handle that identifies the image. This
                                  parameter is passed to the image on entry.
  @param  Status                  The image's exit code.
  @param  ExitDataSize            The size, in bytes, of ExitData. Ignored if
                                  ExitStatus is EFI_SUCCESS.
  @param  ExitData                Pointer to a data buffer that includes a
                                  Null-terminated Unicode string, optionally
                                  followed by additional binary data. The string
                                  is a description that the caller may use to
                                  further indicate the reason for the image's
                                  exit.

  @retval EFI_INVALID_PARAMETER   Image handle is NULL or it is not current
                                  image.
  @retval EFI_SUCCESS             Successfully terminates the currently loaded
                                  EFI image.
  @retval EFI_ACCESS_DENIED       Should never reach there.
  @retval EFI_OUT_OF_RESOURCES    Could not allocate pool

**/
EFI_STATUS
EFIAPI
CoreExit (
  IN EFI_HANDLE  ImageHandle,
  IN EFI_STATUS  Status,
  IN UINTN       ExitDataSize,
  IN CHAR16      *ExitData  OPTIONAL
  )
{
  LOADED_IMAGE_PRIVATE_DATA  *Image;
  EFI_TPL                    OldTpl;

  //
  // Prevent possible reentrance to this function
  // for the same ImageHandle
  //
  OldTpl = CoreRaiseTpl (TPL_NOTIFY);

  Image = CoreLoadedImageInfo (ImageHandle);
  if (Image == NULL) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (!Image->Started) {
    //
    // The image has not been started so just free its resources
    //
    CoreUnloadAndCloseImage (Image, TRUE);
    Status = EFI_SUCCESS;
    goto Done;
  }

  //
  // Image has been started, verify this image can exit
  //
  if (Image != mCurrentImage) {
    DEBUG ((DEBUG_LOAD|DEBUG_ERROR, "Exit: Image is not exitable image\n"));
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  //
  // Set status
  //
  Image->Status = Status;

  //
  // If there's ExitData info, move it
  //
  if (ExitData != NULL) {
    Image->ExitDataSize = ExitDataSize;
    Image->ExitData = AllocatePool (Image->ExitDataSize);
    if (Image->ExitData == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }
    CopyMem (Image->ExitData, ExitData, Image->ExitDataSize);
  }

  CoreRestoreTpl (OldTpl);
  //
  // return to StartImage
  //
  LongJump (Image->JumpContext, (UINTN)-1);

  //
  // If we return from LongJump, then it is an error
  //
  ASSERT (FALSE);
  Status = EFI_ACCESS_DENIED;
Done:
  CoreRestoreTpl (OldTpl);
  return Status;
}




/**
  Unloads an image.

  @param  ImageHandle             Handle that identifies the image to be
                                  unloaded.

  @retval EFI_SUCCESS             The image has been unloaded.
  @retval EFI_UNSUPPORTED         The image has been started, and does not support
                                  unload.
  @retval EFI_INVALID_PARAMPETER  ImageHandle is not a valid image handle.

**/
EFI_STATUS
EFIAPI
CoreUnloadImage (
  IN EFI_HANDLE  ImageHandle
  )
{
  EFI_STATUS                 Status;
  LOADED_IMAGE_PRIVATE_DATA  *Image;

  Image = CoreLoadedImageInfo (ImageHandle);
  if (Image == NULL ) {
    //
    // The image handle is not valid
    //
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (Image->Started) {
    //
    // The image has been started, request it to unload.
    //
    Status = EFI_UNSUPPORTED;
    if (Image->Info.Unload != NULL) {
      Status = Image->Info.Unload (ImageHandle);
    }

  } else {
    //
    // This Image hasn't been started, thus it can be unloaded
    //
    Status = EFI_SUCCESS;
  }


  if (!EFI_ERROR (Status)) {
    //
    // if the Image was not started or Unloaded O.K. then clean up
    //
    CoreUnloadAndCloseImage (Image, TRUE);
  }

Done:
  return Status;
}
