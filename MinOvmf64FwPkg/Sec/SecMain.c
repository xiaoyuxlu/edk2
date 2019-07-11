/** @file
  Main SEC phase code.  Transitions to PEI.

  Copyright (c) 2008 - 2015, Intel Corporation. All rights reserved.<BR>
  (C) Copyright 2016 Hewlett Packard Enterprise Development LP<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <OvmfPlatforms.h>
#include <Library/PeimEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PeiServicesLib.h>
#include <Library/PcdLib.h>
#include <Library/PciLib.h>
#include <Library/PciExpressLib.h>
#include <Library/UefiCpuLib.h>
#include <Library/IoLib.h>
#include <Library/PeCoffLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/PeCoffExtraActionLib.h>
#include <Library/ElfLoaderLib.h>
#include <Library/LocalApicLib.h>
#include <Library/HobLib.h>
#include <Library/QemuFwCfgLib.h>

#define MCH_PCIEXBAR_LOW      0x60
#define MCH_PCIEXBAR_EN         BIT0
#define MCH_PCIEXBAR_HIGH     0x64
#define ICH9_PMBASE_VALUE 0x0600
#define ICH9_PMBASE               0x40
#define ICH9_PMBASE_MASK            (BIT15 | BIT14 | BIT13 | BIT12 | BIT11 | \
                                     BIT10 | BIT9  | BIT8  | BIT7)
#define ICH9_ACPI_CNTL            0x44
#define ICH9_ACPI_CNTL_ACPI_EN      BIT7

typedef
VOID
(EFIAPI *EFI_DXE_CORE_ENTRY_POINT) (
  IN CONST EFI_PEI_HOB_POINTERS *HobList
  );

typedef struct {
  EFI_HOB_HANDOFF_INFO_TABLE       PHIT;
  EFI_HOB_FIRMWARE_VOLUME          FirmwareVolume;  
  EFI_HOB_CPU                      Cpu;
  EFI_HOB_MEMORY_ALLOCATION        HypervisorFw;
  EFI_HOB_MEMORY_ALLOCATION        PageTable;
  EFI_HOB_MEMORY_ALLOCATION_STACK  Stack;
  EFI_HOB_RESOURCE_DESCRIPTOR      MemoryAbove1MB;
  EFI_HOB_RESOURCE_DESCRIPTOR      MemoryBelow1MB;
  EFI_HOB_GENERIC_HEADER           EndOfHob;
} HOB_TEMPLATE;

EFI_GUID mHypervisorFwGuid = {0x6948d4a, 0xd359, 0x4721, {0xad, 0xf6, 0x52, 0x25, 0x48, 0x5a, 0x6a, 0x3a}};

UINT8
EFIAPI
CmosRead8 (
  IN      UINTN                     Index
  )
{
  IoWrite8 (0x70, (UINT8) Index);
  return IoRead8 (0x71);
}

UINT8
EFIAPI
CmosWrite8 (
  IN      UINTN                     Index,
  IN      UINT8                     Value
  )
{
  IoWrite8 (0x70, (UINT8) Index);
  IoWrite8 (0x71, Value);
  return Value;
}

UINT32
GetSystemMemorySizeBelow4gb (
  VOID
  )
{
  UINT8 Cmos0x34;
  UINT8 Cmos0x35;


  Cmos0x34 = (UINT8) CmosRead8 (0x34);
  Cmos0x35 = (UINT8) CmosRead8 (0x35);

  return (UINT32) (((UINTN)((Cmos0x35 << 8) + Cmos0x34) << 16) + SIZE_16MB);
}

VOID
PrepareHeaderHOB (
  IN OUT HOB_TEMPLATE *Hob
  )
{
  Hob->EndOfHob.HobType = EFI_HOB_TYPE_END_OF_HOB_LIST;
  Hob->EndOfHob.HobLength = sizeof(EFI_HOB_GENERIC_HEADER);
  Hob->EndOfHob.Reserved = 0;
}

VOID
PrepareResourceDescriptorHOB (
  IN OUT EFI_HOB_RESOURCE_DESCRIPTOR  *Ptr,
  IN     EFI_RESOURCE_TYPE            ResourceType,
  IN     EFI_RESOURCE_ATTRIBUTE_TYPE  ResourceAttribute,
  IN     EFI_PHYSICAL_ADDRESS         MemoryBase,
  IN     UINT64                       MemorySize
  )
{
  Ptr->Header.HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR;
  Ptr->Header.HobLength = sizeof(EFI_HOB_RESOURCE_DESCRIPTOR);
  Ptr->Header.Reserved = 0;
  Ptr->ResourceType = ResourceType;
  Ptr->ResourceAttribute = ResourceAttribute;
  Ptr->PhysicalStart = MemoryBase;
  Ptr->ResourceLength = MemorySize;  
}

VOID
PreparePHITHOB (
  IN OUT HOB_TEMPLATE *Hob
  )
{
  Hob->PHIT.Header.HobType = EFI_HOB_TYPE_HANDOFF;
  Hob->PHIT.Header.HobLength = sizeof(EFI_HOB_HANDOFF_INFO_TABLE);
  Hob->PHIT.Header.Reserved = 0;
  Hob->PHIT.Version = 0x9;
  Hob->PHIT.BootMode = 0x0;
  Hob->PHIT.EfiMemoryTop = GetSystemMemorySizeBelow4gb ();
  Hob->PHIT.EfiMemoryBottom = Hob->PHIT.EfiMemoryTop - SIZE_16MB;
  Hob->PHIT.EfiFreeMemoryTop = Hob->PHIT.EfiMemoryTop;
  Hob->PHIT.EfiFreeMemoryBottom = Hob->PHIT.EfiMemoryBottom + EFI_PAGES_TO_SIZE(EFI_SIZE_TO_PAGES(sizeof(HOB_TEMPLATE)));
  Hob->PHIT.EfiEndOfHobList = Hob->PHIT.EfiMemoryBottom + sizeof(HOB_TEMPLATE);
}

VOID
PrepareCpuHOB (
  IN OUT HOB_TEMPLATE *Hob
  )
{
  UINT32 CpuidEax;
  Hob->Cpu.SizeOfMemorySpace = 36;
  Hob->Cpu.Header.HobType = EFI_HOB_TYPE_CPU;
  Hob->Cpu.Header.HobLength = sizeof(EFI_HOB_CPU);
  Hob->Cpu.Header.Reserved = 0;
  AsmCpuid (0x80000000, &CpuidEax, NULL, NULL, NULL);
  if(CpuidEax > 0x80000008) {
    AsmCpuid(0x80000008, &CpuidEax, NULL, NULL, NULL);
    Hob->Cpu.SizeOfMemorySpace = (UINT8)(CpuidEax & 0xFF); 
  }
  Hob->Cpu.SizeOfIoSpace = 16;
  ZeroMem (Hob->Cpu.Reserved, sizeof(Hob->Cpu.Reserved));
}

VOID
PrepareFvHOB (
  IN OUT HOB_TEMPLATE *Hob,
  IN     UINT64       BFVBase
  )
{
  Hob->FirmwareVolume.Header.HobType = EFI_HOB_TYPE_FV;
  Hob->FirmwareVolume.Header.HobLength = sizeof(EFI_HOB_FIRMWARE_VOLUME);
  Hob->FirmwareVolume.Header.Reserved = 0;
  Hob->FirmwareVolume.Length = PcdGet32(PcdOvmfDxeMemFvSize);
  DEBUG((DEBUG_INFO, "BFVBase: 0x%lx \n", BFVBase));
  Hob->FirmwareVolume.BaseAddress = BFVBase - PcdGet32(PcdOvmfDxeMemFvSize);
}

VOID
PrepareStackHOB(
  IN OUT HOB_TEMPLATE  *Hob
  )
{
  Hob->Stack.Header.HobType = EFI_HOB_TYPE_MEMORY_ALLOCATION;
  Hob->Stack.Header.HobLength = sizeof(EFI_HOB_MEMORY_ALLOCATION_STACK);
  Hob->Stack.Header.Reserved = 0;

  Hob->Stack.AllocDescriptor.MemoryLength = PcdGet32 (PcdOvmfSecPeiTempRamSize);
  Hob->Stack.AllocDescriptor.MemoryBaseAddress = PcdGet32 (PcdOvmfSecPeiTempRamBase);
  Hob->Stack.AllocDescriptor.MemoryType = EfiBootServicesData;

  ZeroMem (Hob->Stack.AllocDescriptor.Reserved, sizeof(Hob->Stack.AllocDescriptor.Reserved));

  CopyMem(&Hob->Stack.AllocDescriptor.Name, &gEfiHobMemoryAllocStackGuid, sizeof(EFI_GUID));
}

VOID
PreparePageTableHOB(
  IN OUT HOB_TEMPLATE  *Hob,
  IN UINTN             PageTableSize
  )
{
  Hob->PageTable.Header.HobType = EFI_HOB_TYPE_MEMORY_ALLOCATION;
  Hob->PageTable.Header.HobLength = sizeof(EFI_HOB_MEMORY_ALLOCATION);
  Hob->PageTable.Header.Reserved = 0;

  Hob->PageTable.AllocDescriptor.MemoryLength = PageTableSize;
  Hob->PageTable.AllocDescriptor.MemoryBaseAddress = AsmReadCr3();
  Hob->PageTable.AllocDescriptor.MemoryType = EfiBootServicesData;

  ZeroMem (Hob->PageTable.AllocDescriptor.Reserved, sizeof(Hob->PageTable.AllocDescriptor.Reserved));

  CopyMem(&Hob->PageTable.AllocDescriptor.Name, &gEfiHobMemoryAllocModuleGuid, sizeof(EFI_GUID));
}

UINT64
PrepareHypervisorFwHOB (
  IN OUT HOB_TEMPLATE *Hob,
  IN VOID             *Base, OPTIONAL
  IN UINTN            Pages
  )
{
  UINT64 HypervisorFwBase;

  Hob->HypervisorFw.Header.HobType = EFI_HOB_TYPE_MEMORY_ALLOCATION;
  Hob->HypervisorFw.Header.HobLength = sizeof(EFI_HOB_MEMORY_ALLOCATION);
  Hob->HypervisorFw.Header.Reserved = 0;
  Hob->HypervisorFw.AllocDescriptor.MemoryLength = EFI_PAGES_TO_SIZE(Pages);

  if (Base == NULL) {
    Hob->HypervisorFw.AllocDescriptor.MemoryBaseAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)Hob->PHIT.EfiFreeMemoryTop - Hob->HypervisorFw.AllocDescriptor.MemoryLength;
    Hob->PHIT.EfiFreeMemoryTop -= Hob->HypervisorFw.AllocDescriptor.MemoryLength;
  } else {
    Hob->HypervisorFw.AllocDescriptor.MemoryBaseAddress = (UINTN)Base;
  }
  HypervisorFwBase = Hob->HypervisorFw.AllocDescriptor.MemoryBaseAddress;
  ZeroMem ((VOID *)(UINTN)HypervisorFwBase, EFI_PAGES_TO_SIZE(Pages));

  CopyMem(&Hob->HypervisorFw.AllocDescriptor.Name, &mHypervisorFwGuid, sizeof(EFI_GUID));
  Hob->HypervisorFw.AllocDescriptor.MemoryType = EfiBootServicesCode;
  ZeroMem (Hob->HypervisorFw.AllocDescriptor.Reserved, sizeof(Hob->HypervisorFw.AllocDescriptor.Reserved));

  return HypervisorFwBase; 
}

/**
  Locates a section within a series of sections
  with the specified section type.

  The Instance parameter indicates which instance of the section
  type to return. (0 is first instance, 1 is second...)

  @param[in]   Sections        The sections to search
  @param[in]   SizeOfSections  Total size of all sections
  @param[in]   SectionType     The section type to locate
  @param[in]   Instance        The section instance number
  @param[out]  FoundSection    The FFS section if found

  @retval EFI_SUCCESS           The file and section was found
  @retval EFI_NOT_FOUND         The file and section was not found
  @retval EFI_VOLUME_CORRUPTED  The firmware volume was corrupted

**/
EFI_STATUS
FindFfsSectionInstance (
  IN  VOID                             *Sections,
  IN  UINTN                            SizeOfSections,
  IN  EFI_SECTION_TYPE                 SectionType,
  IN  UINTN                            Instance,
  OUT EFI_COMMON_SECTION_HEADER        **FoundSection
  )
{
  EFI_PHYSICAL_ADDRESS        CurrentAddress;
  UINT32                      Size;
  EFI_PHYSICAL_ADDRESS        EndOfSections;
  EFI_COMMON_SECTION_HEADER   *Section;
  EFI_PHYSICAL_ADDRESS        EndOfSection;

  //
  // Loop through the FFS file sections within the PEI Core FFS file
  //
  EndOfSection = (EFI_PHYSICAL_ADDRESS)(UINTN) Sections;
  EndOfSections = EndOfSection + SizeOfSections;
  for (;;) {
    if (EndOfSection == EndOfSections) {
      break;
    }
    CurrentAddress = (EndOfSection + 3) & ~(3ULL);
    if (CurrentAddress >= EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    Section = (EFI_COMMON_SECTION_HEADER*)(UINTN) CurrentAddress;

    Size = SECTION_SIZE (Section);
    if (Size < sizeof (*Section)) {
      return EFI_VOLUME_CORRUPTED;
    }

    EndOfSection = CurrentAddress + Size;
    if (EndOfSection > EndOfSections) {
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Look for the requested section type
    //
    if (Section->Type == SectionType) {
      if (Instance == 0) {
        *FoundSection = Section;
        return EFI_SUCCESS;
      } else {
        Instance--;
      }
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Locates a section within a series of sections
  with the specified section type.

  @param[in]   Sections        The sections to search
  @param[in]   SizeOfSections  Total size of all sections
  @param[in]   SectionType     The section type to locate
  @param[out]  FoundSection    The FFS section if found

  @retval EFI_SUCCESS           The file and section was found
  @retval EFI_NOT_FOUND         The file and section was not found
  @retval EFI_VOLUME_CORRUPTED  The firmware volume was corrupted

**/
EFI_STATUS
FindFfsSectionInSections (
  IN  VOID                             *Sections,
  IN  UINTN                            SizeOfSections,
  IN  EFI_SECTION_TYPE                 SectionType,
  OUT EFI_COMMON_SECTION_HEADER        **FoundSection
  )
{
  return FindFfsSectionInstance (
           Sections,
           SizeOfSections,
           SectionType,
           0,
           FoundSection
           );
}

/**
  Locates a FFS file with the specified file type and a section
  within that file with the specified section type.

  @param[in]   Fv            The firmware volume to search
  @param[in]   FileType      The file type to locate
  @param[in]   SectionType   The section type to locate
  @param[out]  FoundSection  The FFS section if found

  @retval EFI_SUCCESS           The file and section was found
  @retval EFI_NOT_FOUND         The file and section was not found
  @retval EFI_VOLUME_CORRUPTED  The firmware volume was corrupted

**/
EFI_STATUS
FindFfsFileAndSection (
  IN  EFI_FIRMWARE_VOLUME_HEADER       *Fv,
  IN  EFI_FV_FILETYPE                  FileType,
  IN  EFI_SECTION_TYPE                 SectionType,
  OUT EFI_COMMON_SECTION_HEADER        **FoundSection
  )
{
  EFI_STATUS                  Status;
  EFI_PHYSICAL_ADDRESS        CurrentAddress;
  EFI_PHYSICAL_ADDRESS        EndOfFirmwareVolume;
  EFI_FFS_FILE_HEADER         *File;
  UINT32                      Size;
  EFI_PHYSICAL_ADDRESS        EndOfFile;

  if (Fv->Signature != EFI_FVH_SIGNATURE) {
    DEBUG ((EFI_D_ERROR, "FV at %p does not have FV header signature\n", Fv));
    return EFI_VOLUME_CORRUPTED;
  }

  CurrentAddress = (EFI_PHYSICAL_ADDRESS)(UINTN) Fv;
  EndOfFirmwareVolume = CurrentAddress + Fv->FvLength;

  //
  // Loop through the FFS files in the Boot Firmware Volume
  //
  for (EndOfFile = CurrentAddress + Fv->HeaderLength; ; ) {

    CurrentAddress = (EndOfFile + 7) & ~(7ULL);
    if (CurrentAddress > EndOfFirmwareVolume) {
      return EFI_VOLUME_CORRUPTED;
    }

    File = (EFI_FFS_FILE_HEADER*)(UINTN) CurrentAddress;
    Size = FFS_FILE_SIZE (File);
    if (Size < (sizeof (*File) + sizeof (EFI_COMMON_SECTION_HEADER))) {
      return EFI_VOLUME_CORRUPTED;
    }

    EndOfFile = CurrentAddress + Size;
    if (EndOfFile > EndOfFirmwareVolume) {
      return EFI_VOLUME_CORRUPTED;
    }

    //
    // Look for the request file type
    //
    if (File->Type != FileType) {
      continue;
    }

    Status = FindFfsSectionInSections (
               (VOID*) (File + 1),
               (UINTN) EndOfFile - (UINTN) (File + 1),
               SectionType,
               FoundSection
               );
    if (!EFI_ERROR (Status) || (Status == EFI_VOLUME_CORRUPTED)) {
      return Status;
    }
  }
}



EFI_STATUS
FindHypervisorFwImageBaseInFv (
  IN  EFI_FIRMWARE_VOLUME_HEADER        *Fv,
  OUT  EFI_PHYSICAL_ADDRESS             *HypervisorFwImageBase
  )
{
  EFI_STATUS                  Status;
  EFI_COMMON_SECTION_HEADER   *Section;

  Status = FindFfsFileAndSection (
             Fv,
             EFI_FV_FILETYPE_DXE_CORE,
             EFI_SECTION_PE32,
             &Section
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Unable to find Hypervisor FW image\n"));
    return Status;
  }

  *HypervisorFwImageBase = (EFI_PHYSICAL_ADDRESS)(UINTN)(Section + 1);
  return EFI_SUCCESS;
}

/*
  Find and return Hypervisor FW entry point.
**/
VOID
FindAndReportEntryPoints (
  IN  OUT HOB_TEMPLATE                 *Hob,
  OUT UINTN                            *HypervisorFwEntryPoint
  )
{
  EFI_STATUS                       Status;
  EFI_FIRMWARE_VOLUME_HEADER       *FirmwareVolumePtr;
  VOID                             *BaseHypervisorFw;
  EFI_PHYSICAL_ADDRESS             HypervisorFwImageBase;
  PE_COFF_LOADER_IMAGE_CONTEXT     ImageContext;
  UINTN                            Pages;
  UINTN                            Size;

  *HypervisorFwEntryPoint = 0;
  FirmwareVolumePtr = (VOID *)(UINTN)Hob->FirmwareVolume.BaseAddress;
  FindHypervisorFwImageBaseInFv (FirmwareVolumePtr, &HypervisorFwImageBase);

  if (*(UINT16 *)(UINTN)HypervisorFwImageBase == EFI_IMAGE_DOS_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "PE FW Image\n"));
    ImageContext.Handle = (VOID *)(UINTN)HypervisorFwImageBase;
    ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;
    Status = PeCoffLoaderGetImageInfo(&ImageContext);
    if (ImageContext.SectionAlignment > EFI_PAGE_SIZE) {
      Pages = EFI_SIZE_TO_PAGES ((UINTN) (ImageContext.ImageSize + ImageContext.SectionAlignment));
    } else {
      Pages = EFI_SIZE_TO_PAGES ((UINTN) ImageContext.ImageSize);
    }
    BaseHypervisorFw = (VOID *)(UINTN)PrepareHypervisorFwHOB(Hob, NULL, Pages);

    ImageContext.ImageAddress = (PHYSICAL_ADDRESS)(UINTN)BaseHypervisorFw;
    ImageContext.ImageAddress += ImageContext.SectionAlignment -1 ;
    ImageContext.ImageAddress &= ~((UINTN)ImageContext.SectionAlignment -1);
    Status = PeCoffLoaderLoadImage(&ImageContext);
    ASSERT_EFI_ERROR(Status);
    Status = PeCoffLoaderRelocateImage(&ImageContext);
    ASSERT_EFI_ERROR(Status);
    Status = PeCoffLoaderGetEntryPoint ((VOID *) (UINTN) ImageContext.ImageAddress, (VOID**) HypervisorFwEntryPoint);
    ASSERT_EFI_ERROR(Status);
  } else if (*(UINT32*)(UINTN)HypervisorFwImageBase == *(UINT32 *)ELFMAG) {
    DEBUG ((DEBUG_ERROR, "ELF FW Image\n"));
    DumpElf ((VOID *)(UINTN)HypervisorFwImageBase);
    Status = GetElfImageInfo ((VOID *)(UINTN)HypervisorFwImageBase, 0, &BaseHypervisorFw, &Size, HypervisorFwEntryPoint);
    DEBUG ((DEBUG_ERROR, "BaseHypervisorFw - 0x%x\n", BaseHypervisorFw));
    DEBUG ((DEBUG_ERROR, "Size - 0x%x\n", Size));
    DEBUG ((DEBUG_ERROR, "HypervisorFwEntryPoint - 0x%x\n", HypervisorFwEntryPoint));
    ASSERT_EFI_ERROR(Status);
    BaseHypervisorFw = (VOID *)(UINTN)PrepareHypervisorFwHOB(Hob, BaseHypervisorFw, EFI_SIZE_TO_PAGES(Size));
    Status = LoadElfImageData ((VOID *)(UINTN)HypervisorFwImageBase, 0, BaseHypervisorFw, Size, HypervisorFwEntryPoint);
    ASSERT_EFI_ERROR(Status);
  } else {
    DEBUG ((DEBUG_ERROR, "Unknown FW Image\n"));
    CpuDeadLoop();
  }
}

VOID *
FinalizeHob (
  IN  OUT HOB_TEMPLATE                 *Hob
  )
{
  CopyMem ((VOID *)(UINTN)Hob->PHIT.EfiMemoryBottom, Hob, sizeof(HOB_TEMPLATE));
  return (VOID *)(UINTN)Hob->PHIT.EfiMemoryBottom;
}

VOID
PciExBarInitialization (
  VOID
  )
{
  union {
    UINT64 Uint64;
    UINT32 Uint32[2];
  } PciExBarBase;

  //
  // We only support the 256MB size for the MMCONFIG area:
  // 256 buses * 32 devices * 8 functions * 4096 bytes config space.
  //
  // The masks used below enforce the Q35 requirements that the MMCONFIG area
  // be (a) correctly aligned -- here at 256 MB --, (b) located under 64 GB.
  //
  // Note that (b) also ensures that the minimum address width we have
  // determined in AddressWidthInitialization(), i.e., 36 bits, will suffice
  // for DXE's page tables to cover the MMCONFIG area.
  //
  PciExBarBase.Uint64 = FixedPcdGet64 (PcdPciExpressBaseAddress);

  //
  // Clear the PCIEXBAREN bit first, before programming the high register.
  //
  PciWrite32 (PCI_LIB_ADDRESS (0, 0, 0, MCH_PCIEXBAR_LOW), 0);

  //
  // Program the high register. Then program the low register, setting the
  // MMCONFIG area size and enabling decoding at once.
  //
  PciWrite32 (PCI_LIB_ADDRESS (0, 0, 0, MCH_PCIEXBAR_HIGH), PciExBarBase.Uint32[1]);
  PciWrite32 (
    PCI_LIB_ADDRESS (0, 0, 0, MCH_PCIEXBAR_LOW),
    PciExBarBase.Uint32[0] | MCH_PCIEXBAR_EN
    );
}

VOID
InitializeAcpiPm (
  VOID
  )
{
  UINTN         PmCmd;
  UINTN         Pmba;
  UINT32        PmbaAndVal;
  UINT32        PmbaOrVal;
  UINTN         AcpiCtlReg;
  UINT8         AcpiEnBit;

  PmCmd      = PCI_LIB_ADDRESS (0, 0x1f, 0, PCI_COMMAND_OFFSET);
  Pmba       = PCI_LIB_ADDRESS (0, 0x1f, 0, ICH9_PMBASE);
  PmbaAndVal = ~(UINT32)ICH9_PMBASE_MASK;
  PmbaOrVal  = ICH9_PMBASE_VALUE;
  AcpiCtlReg = PCI_LIB_ADDRESS (0, 0x1f, 0, ICH9_ACPI_CNTL);
  AcpiEnBit  = ICH9_ACPI_CNTL_ACPI_EN;

  if ((PciRead8 (AcpiCtlReg) & AcpiEnBit) == 0) {
    //
    // The PEI phase should be exited with fully accessibe ACPI PM IO space:
    // 1. set PMBA
    //
    PciAndThenOr32 (Pmba, PmbaAndVal, PmbaOrVal);

    //
    // 2. set PCICMD/IOSE
    //
    PciOr8 (PmCmd, EFI_PCI_COMMAND_IO_SPACE);

    //
    // 3. set ACPI PM IO enable bit (PMREGMISC:PMIOSE or ACPI_CNTL:ACPI_EN)
    //
    PciOr8 (AcpiCtlReg, AcpiEnBit);
  }
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

VOID
InitPci (
  VOID
  )
{
  PciWrite32 (PCI_LIB_ADDRESS (0, 3, 0, 0x14), 0xC1085000); // BAR1: MEM32
  PciWrite32 (PCI_LIB_ADDRESS (0, 3, 0, 0x20), 0xC200000C); // BAR4: PMEM64
  PciWrite32 (PCI_LIB_ADDRESS (0, 3, 0, 0x24), 0x00000008);
  PciWrite8 (PCI_LIB_ADDRESS (0, 3, 0, 0x4), 0x07);
}

VOID
TestVirtIoBlk (
  VOID
  )
{
  UINTN  Base;

  Base = LShiftU64 (PciRead32 (PCI_LIB_ADDRESS (0, 3, 0, 0x24)), 32) | PciRead32 (PCI_LIB_ADDRESS (0, 3, 0, 0x20)) & ~0xFull;
  DEBUG((DEBUG_INFO, "VirtIoBlk - 0x%016lx\n", (UINT64)Base));

  DEBUG((DEBUG_INFO, "VIRTIO_STATUS_RESET\n"));
  MmioWrite32(Base + 0x14, 0);
  DEBUG((DEBUG_INFO, "VIRTIO_STATUS_ACKNOWLEDGE\n"));
  MmioWrite32(Base + 0x14, 1);
  DEBUG((DEBUG_INFO, "VIRTIO_STATUS_DRIVER\n"));
  MmioWrite32(Base + 0x14, 2);

  DEBUG((DEBUG_INFO, "Magic    - 0x%08x\n", MmioRead32(Base + 0))); // 1
  DEBUG((DEBUG_INFO, "Version  - 0x%08x\n", MmioRead32(Base + 4))); // 1
  DEBUG((DEBUG_INFO, "DeviceID - 0x%08x\n", MmioRead32(Base + 8))); // 1
  DEBUG((DEBUG_INFO, "VendorID - 0x%08x\n", MmioRead32(Base + 0xC))); // 1
  DEBUG((DEBUG_INFO, "DeviceFeatures    - 0x%08x\n", MmioRead32(Base + 0x10))); // 100FF
  DEBUG((DEBUG_INFO, "DeviceFeaturesSel - 0x%08x\n", MmioRead32(Base + 0x14))); // F
  DEBUG((DEBUG_INFO, "DriverFeatures    - 0x%08x\n", MmioRead32(Base + 0x20))); // FF0080
  DEBUG((DEBUG_INFO, "DriverFeaturesSel - 0x%08x\n", MmioRead32(Base + 0x24))); // 1
  DEBUG((DEBUG_INFO, "QueueSel          - 0x%08x\n", MmioRead32(Base + 0x30)));
  DEBUG((DEBUG_INFO, "QueueNumMax       - 0x%08x\n", MmioRead32(Base + 0x34)));
  DEBUG((DEBUG_INFO, "QueueNum          - 0x%08x\n", MmioRead32(Base + 0x38)));
  DEBUG((DEBUG_INFO, "QueueReady        - 0x%08x\n", MmioRead32(Base + 0x44)));
  DEBUG((DEBUG_INFO, "QueueNotify       - 0x%08x\n", MmioRead32(Base + 0x50)));
  DEBUG((DEBUG_INFO, "InterruptStatus   - 0x%08x\n", MmioRead32(Base + 0x60)));
  DEBUG((DEBUG_INFO, "InterruptACK      - 0x%08x\n", MmioRead32(Base + 0x64)));
  DEBUG((DEBUG_INFO, "Status            - 0x%08x\n", MmioRead32(Base + 0x70)));
}

UINTN
CreateHostPaging (
  VOID
  );

VOID
EFIAPI
SecCoreStartupWithStack (
  IN EFI_FIRMWARE_VOLUME_HEADER       *BootFv,
  IN VOID                             *TopOfCurrentStack
  )
{
  UINTN         HypervisorFwEntryPoint;
  HOB_TEMPLATE  HOB;
  VOID          *FinalHob;
  UINTN         PageTableSize;

  DEBUG((DEBUG_INFO, " EfiTop: 0x%lx\n", (UINT64)((UINTN)(UINT8 *)TopOfCurrentStack - (UINTN)PcdGet32(PcdOvmfSecPeiTempRamSize)))); 

  DEBUG((DEBUG_INFO, " PcdOvmfDxeMemFvBase: 0x%x\n", PcdGet32(PcdOvmfDxeMemFvBase)));
  DEBUG((DEBUG_INFO, " PcdOvmfDxeMemFvSize: 0x%x\n", PcdGet32(PcdOvmfDxeMemFvSize)));
  DEBUG((DEBUG_INFO, " PcdOvmfPeiMemFvBase: 0x%x\n", PcdGet32(PcdOvmfPeiMemFvBase)));
  DEBUG((DEBUG_INFO, " PcdOvmfPeiMemFvSize: 0x%x\n", PcdGet32(PcdOvmfPeiMemFvSize)));
  DEBUG((DEBUG_INFO, " PcdOvmfSecPageTablesBase: 0x%x\n", PcdGet32(PcdOvmfSecPageTablesBase)));
  DEBUG((DEBUG_INFO, " PcdOvmfSecPeiTempRamBase: 0x%x\n", PcdGet32(PcdOvmfSecPeiTempRamBase)));
  DEBUG((DEBUG_INFO, " PcdOvmfSecPeiTempRamSize: 0x%x\n", PcdGet32(PcdOvmfSecPeiTempRamSize)));

  SetApicMode (LOCAL_APIC_MODE_X2APIC);
  DEBUG((DEBUG_INFO, " SetApicMode: Done\n")); 
  InitializeApicTimer (0, MAX_UINT32, TRUE, 5);
  DisableApicTimerInterrupt ();
  
  PreparePHITHOB(&HOB);
  PrepareCpuHOB(&HOB);

  PrepareFvHOB (&HOB, (UINT64)(UINTN)BootFv); 

  PrepareStackHOB(&HOB);
  PageTableSize = CreateHostPaging ();
  PreparePageTableHOB(&HOB, PageTableSize);

  UINT32 LowerMemorySize = GetSystemMemorySizeBelow4gb ();
  DEBUG((DEBUG_INFO, "Total LowerMemorySize : %llx \n", LowerMemorySize));
  PrepareResourceDescriptorHOB(
    &(HOB.MemoryAbove1MB),
    EFI_RESOURCE_SYSTEM_MEMORY,
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
      EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
      EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
      EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
      EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
      EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE |
      EFI_RESOURCE_ATTRIBUTE_TESTED,
    BASE_1MB, 
    (UINT64)(LowerMemorySize - BASE_1MB)
    );
  PrepareResourceDescriptorHOB(
    &(HOB.MemoryBelow1MB),
    EFI_RESOURCE_SYSTEM_MEMORY,
    EFI_RESOURCE_ATTRIBUTE_PRESENT |
      EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
      EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
      EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
      EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
      EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE |
      EFI_RESOURCE_ATTRIBUTE_TESTED,
    0,
    BASE_512KB + BASE_128KB
    );
  PrepareHeaderHOB(&HOB);

  //
  // Clear 8259 interrupt
  //
  IoWrite8 (0x21, 0xff);
  IoWrite8 (0xA1, 0xff);

  //
  // Disable A20 Mask
  //
  IoOr8 (0x92, BIT1);

  InitializeAcpiPm ();

  //
  // Set Root Complex Register Block BAR
  //
  /*
  PciWrite32 (
    POWER_MGMT_REGISTER_Q35 (ICH9_RCBA),
    ICH9_ROOT_COMPLEX_BASE | ICH9_RCBA_EN
    );
    */
  PciExBarInitialization ();

  ProgramVirtualWireMode();
  DisableLvtInterrupts();

  InitPci ();

  TestVirtIoBlk ();

  FindAndReportEntryPoints(&HOB, &HypervisorFwEntryPoint);

  DEBUG ((DEBUG_INFO, "Hob - 0x%x\n", &HOB));
  DEBUG ((DEBUG_INFO, "Hob->PHIT.EfiMemoryTop - 0x%x\n", HOB.PHIT.EfiMemoryTop));
  DEBUG ((DEBUG_INFO, "Hob->PHIT.EfiMemoryBottom - 0x%x\n", HOB.PHIT.EfiMemoryBottom));
  DEBUG ((DEBUG_INFO, "Hob->PHIT.EfiFreeMemoryTop - 0x%x\n", HOB.PHIT.EfiFreeMemoryTop));
  DEBUG ((DEBUG_INFO, "Hob->PHIT.EfiFreeMemoryBottom - 0x%x\n", HOB.PHIT.EfiFreeMemoryBottom));
  DEBUG ((DEBUG_INFO, "Hob->MemoryAbove1MB.PhysicalStart - 0x%x\n", HOB.MemoryAbove1MB.PhysicalStart));
  DEBUG ((DEBUG_INFO, "Hob->MemoryAbove1MB.ResourceLength - 0x%x\n", HOB.MemoryAbove1MB.ResourceLength));
  DEBUG ((DEBUG_INFO, "Hob->MemoryBelow1MB.PhysicalStart - 0x%x\n", HOB.MemoryBelow1MB.PhysicalStart));
  DEBUG ((DEBUG_INFO, "Hob->MemoryBelow1MB.ResourceLength - 0x%x\n", HOB.MemoryBelow1MB.ResourceLength));
  DEBUG ((DEBUG_INFO, "Hob->FirmwareVolume.BaseAddress - 0x%x\n", HOB.FirmwareVolume.BaseAddress));
  DEBUG ((DEBUG_INFO, "Hob->FirmwareVolume.Length - 0x%x\n", HOB.FirmwareVolume.Length));
  DEBUG ((DEBUG_INFO, "Hob->Stack.AllocDescriptor.MemoryBaseAddress - 0x%x\n", HOB.Stack.AllocDescriptor.MemoryBaseAddress));
  DEBUG ((DEBUG_INFO, "Hob->Stack.AllocDescriptor.MemoryLength - 0x%x\n", HOB.Stack.AllocDescriptor.MemoryLength));
  DEBUG ((DEBUG_INFO, "Hob->PageTable.AllocDescriptor.MemoryBaseAddress - 0x%x\n", HOB.PageTable.AllocDescriptor.MemoryBaseAddress));
  DEBUG ((DEBUG_INFO, "Hob->PageTable.AllocDescriptor.MemoryLength - 0x%x\n", HOB.PageTable.AllocDescriptor.MemoryLength));
  DEBUG ((DEBUG_INFO, "Hob->HypervisorFw.AllocDescriptor.MemoryBaseAddress - 0x%x\n", HOB.HypervisorFw.AllocDescriptor.MemoryBaseAddress));
  DEBUG ((DEBUG_INFO, "Hob->HypervisorFw.AllocDescriptor.MemoryLength - 0x%x\n", HOB.HypervisorFw.AllocDescriptor.MemoryLength));
  DEBUG ((DEBUG_INFO, "HypervisorFwEntryPoint - 0x%x\n", HypervisorFwEntryPoint));

  FinalHob = FinalizeHob (&HOB);
  (*(EFI_DXE_CORE_ENTRY_POINT)HypervisorFwEntryPoint) ((EFI_PEI_HOB_POINTERS *)FinalHob);
  ASSERT (FALSE);
  CpuDeadLoop ();
}
  

