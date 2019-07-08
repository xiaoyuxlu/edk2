/** @file
  The file contains the Memory Initialization related services in the EFI Boot Services Table.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeMain.h"

#define MINIMUM_INITIAL_MEMORY_SIZE 0x10000

#define MEMORY_ATTRIBUTE_MASK         (EFI_RESOURCE_ATTRIBUTE_PRESENT             | \
                                       EFI_RESOURCE_ATTRIBUTE_INITIALIZED         | \
                                       EFI_RESOURCE_ATTRIBUTE_TESTED              | \
                                       EFI_RESOURCE_ATTRIBUTE_READ_PROTECTED      | \
                                       EFI_RESOURCE_ATTRIBUTE_WRITE_PROTECTED     | \
                                       EFI_RESOURCE_ATTRIBUTE_EXECUTION_PROTECTED | \
                                       EFI_RESOURCE_ATTRIBUTE_READ_ONLY_PROTECTED | \
                                       EFI_RESOURCE_ATTRIBUTE_16_BIT_IO           | \
                                       EFI_RESOURCE_ATTRIBUTE_32_BIT_IO           | \
                                       EFI_RESOURCE_ATTRIBUTE_64_BIT_IO           | \
                                       EFI_RESOURCE_ATTRIBUTE_PERSISTENT          )

#define TESTED_MEMORY_ATTRIBUTES      (EFI_RESOURCE_ATTRIBUTE_PRESENT     | \
                                       EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
                                       EFI_RESOURCE_ATTRIBUTE_TESTED      )

#define INITIALIZED_MEMORY_ATTRIBUTES (EFI_RESOURCE_ATTRIBUTE_PRESENT     | \
                                       EFI_RESOURCE_ATTRIBUTE_INITIALIZED )

#define PRESENT_MEMORY_ATTRIBUTES     (EFI_RESOURCE_ATTRIBUTE_PRESENT)

#define EXCLUSIVE_MEMORY_ATTRIBUTES   (EFI_MEMORY_UC | EFI_MEMORY_WC | \
                                       EFI_MEMORY_WT | EFI_MEMORY_WB | \
                                       EFI_MEMORY_WP | EFI_MEMORY_UCE)

#define NONEXCLUSIVE_MEMORY_ATTRIBUTES (EFI_MEMORY_XP | EFI_MEMORY_RP | \
                                        EFI_MEMORY_RO)

/**
  Aligns a value to the specified boundary.

  @param  Value                  64 bit value to align
  @param  Alignment              Log base 2 of the boundary to align Value to
  @param  RoundUp                TRUE if Value is to be rounded up to the nearest
                                 aligned boundary.  FALSE is Value is to be
                                 rounded down to the nearest aligned boundary.

  @return A 64 bit value is the aligned to the value nearest Value with an alignment by Alignment.

**/
UINT64
AlignValue (
  IN UINT64   Value,
  IN UINTN    Alignment,
  IN BOOLEAN  RoundUp
  )
{
  UINT64  AlignmentMask;

  AlignmentMask = LShiftU64 (1, Alignment) - 1;
  if (RoundUp) {
    Value += AlignmentMask;
  }
  return Value & (~AlignmentMask);
}


/**
  Aligns address to the page boundary.

  @param  Value                  64 bit address to align

  @return A 64 bit value is the aligned to the value nearest Value with an alignment by Alignment.

**/
UINT64
PageAlignAddress (
  IN UINT64 Value
  )
{
  return AlignValue (Value, EFI_PAGE_SHIFT, TRUE);
}


/**
  Aligns length to the page boundary.

  @param  Value                  64 bit length to align

  @return A 64 bit value is the aligned to the value nearest Value with an alignment by Alignment.

**/
UINT64
PageAlignLength (
  IN UINT64 Value
  )
{
  return AlignValue (Value, EFI_PAGE_SHIFT, FALSE);
}

/**
  Calculate total memory bin size neeeded.

  @return The total memory bin size neeeded.

**/
UINT64
CalculateTotalMemoryBinSizeNeeded (
  VOID
  )
{
  UINTN     Index;
  UINT64    TotalSize;

  //
  // Loop through each memory type in the order specified by the gMemoryTypeInformation[] array
  //
  TotalSize = 0;
  for (Index = 0; gMemoryTypeInformation[Index].Type != EfiMaxMemoryType; Index++) {
    TotalSize += LShiftU64 (gMemoryTypeInformation[Index].NumberOfPages, EFI_PAGE_SHIFT);
  }

  return TotalSize;
}

/**
  External function. Initializes memory services based on the memory
  descriptor HOBs.  This function is responsible for priming the memory
  map, so memory allocations and resource allocations can be made.
  The first part of this function can not depend on any memory services
  until at least one memory descriptor is provided to the memory services.

  @param  HobStart               The start address of the HOB.
  @param  MemoryBaseAddress      Start address of memory region found to init DXE
                                 core.
  @param  MemoryLength           Length of memory region found to init DXE core.

  @retval EFI_SUCCESS            Memory services successfully initialized.

**/
EFI_STATUS
CoreInitializeMemoryServices (
  IN  VOID                  **HobStart,
  OUT EFI_PHYSICAL_ADDRESS  *MemoryBaseAddress,
  OUT UINT64                *MemoryLength
  )
{
  EFI_PEI_HOB_POINTERS               Hob;
  EFI_MEMORY_TYPE_INFORMATION        *EfiMemoryTypeInformation;
  UINTN                              DataSize;
  BOOLEAN                            Found;
  EFI_HOB_HANDOFF_INFO_TABLE         *PhitHob;
  EFI_HOB_RESOURCE_DESCRIPTOR        *ResourceHob;
  EFI_HOB_RESOURCE_DESCRIPTOR        *PhitResourceHob;
  EFI_PHYSICAL_ADDRESS               BaseAddress;
  UINT64                             Length;
  UINT64                             Attributes;
  EFI_PHYSICAL_ADDRESS               TestedMemoryBaseAddress;
  UINT64                             TestedMemoryLength;
  EFI_PHYSICAL_ADDRESS               HighAddress;
  EFI_HOB_GUID_TYPE                  *GuidHob;
  UINT64                             MinimalMemorySizeNeeded;

  //
  // Point at the first HOB.  This must be the PHIT HOB.
  //
  Hob.Raw = *HobStart;
  ASSERT (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_HANDOFF);

  //
  // Initialize the spin locks and maps in the memory services.
  // Also fill in the memory services into the EFI Boot Services Table
  //
  CoreInitializePool ();

  //
  // Initialize Local Variables
  //
  PhitResourceHob       = NULL;
  ResourceHob           = NULL;
  BaseAddress           = 0;
  Length                = 0;
  Attributes            = 0;

  //
  // Cache the PHIT HOB for later use
  //
  PhitHob = Hob.HandoffInformationTable;

  //
  // See if a Memory Type Information HOB is available
  //
  GuidHob = GetFirstGuidHob (&gEfiMemoryTypeInformationGuid);
  if (GuidHob != NULL) {
    EfiMemoryTypeInformation = GET_GUID_HOB_DATA (GuidHob);
    DataSize                 = GET_GUID_HOB_DATA_SIZE (GuidHob);
    if (EfiMemoryTypeInformation != NULL && DataSize > 0 && DataSize <= (EfiMaxMemoryType + 1) * sizeof (EFI_MEMORY_TYPE_INFORMATION)) {
      CopyMem (&gMemoryTypeInformation, EfiMemoryTypeInformation, DataSize);
    }
  }

  //
  // Include the total memory bin size needed to make sure memory bin could be allocated successfully.
  //
  MinimalMemorySizeNeeded = MINIMUM_INITIAL_MEMORY_SIZE + CalculateTotalMemoryBinSizeNeeded ();

  //
  // Find the Resource Descriptor HOB that contains PHIT range EfiFreeMemoryBottom..EfiFreeMemoryTop
  //
  Found  = FALSE;
  for (Hob.Raw = *HobStart; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
    //
    // Skip all HOBs except Resource Descriptor HOBs
    //
    if (GET_HOB_TYPE (Hob) != EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      continue;
    }

    //
    // Skip Resource Descriptor HOBs that do not describe tested system memory
    //
    ResourceHob = Hob.ResourceDescriptor;
    if (ResourceHob->ResourceType != EFI_RESOURCE_SYSTEM_MEMORY) {
      continue;
    }
    if ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) != TESTED_MEMORY_ATTRIBUTES) {
      continue;
    }

    //
    // Skip Resource Descriptor HOBs that do not contain the PHIT range EfiFreeMemoryBottom..EfiFreeMemoryTop
    //
    if (PhitHob->EfiFreeMemoryBottom < ResourceHob->PhysicalStart) {
      continue;
    }
    if (PhitHob->EfiFreeMemoryTop > (ResourceHob->PhysicalStart + ResourceHob->ResourceLength)) {
      continue;
    }

    //
    // Cache the resource descriptor HOB for the memory region described by the PHIT HOB
    //
    PhitResourceHob = ResourceHob;
    Found = TRUE;

    //
    // Compute range between PHIT EfiMemoryTop and the end of the Resource Descriptor HOB
    //
    Attributes  = PhitResourceHob->ResourceAttribute;
    BaseAddress = PageAlignAddress (PhitHob->EfiMemoryTop);
    Length      = PageAlignLength  (ResourceHob->PhysicalStart + ResourceHob->ResourceLength - BaseAddress);
    if (Length < MinimalMemorySizeNeeded) {
      //
      // If that range is not large enough to intialize the DXE Core, then
      // Compute range between PHIT EfiFreeMemoryBottom and PHIT EfiFreeMemoryTop
      //
      BaseAddress = PageAlignAddress (PhitHob->EfiFreeMemoryBottom);
      Length      = PageAlignLength  (PhitHob->EfiFreeMemoryTop - BaseAddress);
      if (Length < MinimalMemorySizeNeeded) {
        //
        // If that range is not large enough to intialize the DXE Core, then
        // Compute range between the start of the Resource Descriptor HOB and the start of the HOB List
        //
        BaseAddress = PageAlignAddress (ResourceHob->PhysicalStart);
        Length      = PageAlignLength  ((UINT64)((UINTN)*HobStart - BaseAddress));
      }
    }
    break;
  }

  //
  // Assert if a resource descriptor HOB for the memory region described by the PHIT was not found
  //
  ASSERT (Found);

  //
  // Take the range in the resource descriptor HOB for the memory region described
  // by the PHIT as higher priority if it is big enough. It can make the memory bin
  // allocated to be at the same memory region with PHIT that has more better compatibility
  // to avoid memory fragmentation for some code practices assume and allocate <4G ACPI memory.
  //
  if (Length < MinimalMemorySizeNeeded) {
    //
    // Search all the resource descriptor HOBs from the highest possible addresses down for a memory
    // region that is big enough to initialize the DXE core.  Always skip the PHIT Resource HOB.
    // The max address must be within the physically addressible range for the processor.
    //
    HighAddress = MAX_ALLOC_ADDRESS;
    for (Hob.Raw = *HobStart; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
      //
      // Skip the Resource Descriptor HOB that contains the PHIT
      //
      if (Hob.ResourceDescriptor == PhitResourceHob) {
        continue;
      }
      //
      // Skip all HOBs except Resource Descriptor HOBs
      //
      if (GET_HOB_TYPE (Hob) != EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
        continue;
      }

      //
      // Skip Resource Descriptor HOBs that do not describe tested system memory below MAX_ALLOC_ADDRESS
      //
      ResourceHob = Hob.ResourceDescriptor;
      if (ResourceHob->ResourceType != EFI_RESOURCE_SYSTEM_MEMORY) {
        continue;
      }
      if ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) != TESTED_MEMORY_ATTRIBUTES) {
        continue;
      }
      if ((ResourceHob->PhysicalStart + ResourceHob->ResourceLength) > (EFI_PHYSICAL_ADDRESS)MAX_ALLOC_ADDRESS) {
        continue;
      }

      //
      // Skip Resource Descriptor HOBs that are below a previously found Resource Descriptor HOB
      //
      if (HighAddress != (EFI_PHYSICAL_ADDRESS)MAX_ALLOC_ADDRESS && ResourceHob->PhysicalStart <= HighAddress) {
        continue;
      }

      //
      // Skip Resource Descriptor HOBs that are not large enough to initilize the DXE Core
      //
      TestedMemoryBaseAddress = PageAlignAddress (ResourceHob->PhysicalStart);
      TestedMemoryLength      = PageAlignLength  (ResourceHob->PhysicalStart + ResourceHob->ResourceLength - TestedMemoryBaseAddress);
      if (TestedMemoryLength < MinimalMemorySizeNeeded) {
        continue;
      }

      //
      // Save the range described by the Resource Descriptor that is large enough to initilize the DXE Core
      //
      BaseAddress = TestedMemoryBaseAddress;
      Length      = TestedMemoryLength;
      Attributes  = ResourceHob->ResourceAttribute;
      HighAddress = ResourceHob->PhysicalStart;
    }
  }

  DEBUG ((EFI_D_INFO, "CoreInitializeMemoryServices:\n"));
  DEBUG ((EFI_D_INFO, "  BaseAddress - 0x%lx Length - 0x%lx MinimalMemorySizeNeeded - 0x%lx\n", BaseAddress, Length, MinimalMemorySizeNeeded));

  //
  // If no memory regions are found that are big enough to initialize the DXE core, then ASSERT().
  //
  ASSERT (Length >= MinimalMemorySizeNeeded);

  //
  // Declare the very first memory region, so the EFI Memory Services are available.
  //
  CoreAddMemoryDescriptor (
    EfiConventionalMemory,
    BaseAddress,
    RShiftU64 (Length, EFI_PAGE_SHIFT),
    (EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB)
    );

  *MemoryBaseAddress = BaseAddress;
  *MemoryLength      = Length;

  return EFI_SUCCESS;
}


/**
  External function. Initializes the GCD and memory services based on the memory
  descriptor HOBs.  This function is responsible for priming the GCD map and the
  memory map, so memory allocations and resource allocations can be made. The
  HobStart will be relocated to a pool buffer.

  @param  HobStart               The start address of the HOB
  @param  MemoryBaseAddress      Start address of memory region found to init DXE
                                 core.
  @param  MemoryLength           Length of memory region found to init DXE core.

  @retval EFI_SUCCESS            GCD services successfully initialized.

**/
EFI_STATUS
CoreInitializeGcdServices (
  IN OUT VOID              **HobStart,
  IN EFI_PHYSICAL_ADDRESS  MemoryBaseAddress,
  IN UINT64                MemoryLength
  )
{
  EFI_PEI_HOB_POINTERS               Hob;
  VOID                               *NewHobList;
  EFI_HOB_HANDOFF_INFO_TABLE         *PhitHob;
  EFI_HOB_RESOURCE_DESCRIPTOR        *ResourceHob;
  EFI_PHYSICAL_ADDRESS               BaseAddress;
  UINT64                             Length;
  EFI_HOB_MEMORY_ALLOCATION          *MemoryHob;

  //
  // Cache the PHIT HOB for later use
  //
  PhitHob = (EFI_HOB_HANDOFF_INFO_TABLE *)(*HobStart);

  //
  // Add rest resource to memory map.
  //
  for (Hob.Raw = *HobStart; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      //
      // Skip Resource Descriptor HOBs that do not describe tested system memory below MAX_ALLOC_ADDRESS
      //
      ResourceHob = Hob.ResourceDescriptor;
      if (ResourceHob->ResourceType != EFI_RESOURCE_SYSTEM_MEMORY) {
        continue;
      }
      if ((ResourceHob->ResourceAttribute & MEMORY_ATTRIBUTE_MASK) != TESTED_MEMORY_ATTRIBUTES) {
        continue;
      }
      if ((ResourceHob->PhysicalStart + ResourceHob->ResourceLength) > (EFI_PHYSICAL_ADDRESS)MAX_ALLOC_ADDRESS) {
        continue;
      }

      //
      // Save the range described by the Resource DescriptorBaseAddress
      //
      BaseAddress = PageAlignAddress (ResourceHob->PhysicalStart);
      Length      = PageAlignLength  (ResourceHob->PhysicalStart + ResourceHob->ResourceLength - BaseAddress);

      if (BaseAddress + Length > PageAlignAddress (PhitHob->EfiMemoryBottom)) {
        Length = PageAlignAddress (PhitHob->EfiMemoryBottom) - BaseAddress;
      }

      CoreAddMemoryDescriptor (
        EfiConventionalMemory,
        BaseAddress,
        RShiftU64 (Length, EFI_PAGE_SHIFT),
        (EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB)
        );
    }
  }

  //
  // Walk the HOB list and allocate all memory space that is consumed by memory allocation HOBs.
  // Also update the EFI Memory Map with the memory allocation HOBs.
  //
  for (Hob.Raw = *HobStart; !END_OF_HOB_LIST(Hob); Hob.Raw = GET_NEXT_HOB(Hob)) {
    if (GET_HOB_TYPE (Hob) == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      MemoryHob = Hob.MemoryAllocation;
      BaseAddress = MemoryHob->AllocDescriptor.MemoryBaseAddress;
      CoreAddMemoryDescriptor (
            MemoryHob->AllocDescriptor.MemoryType,
            MemoryHob->AllocDescriptor.MemoryBaseAddress,
            RShiftU64 (MemoryHob->AllocDescriptor.MemoryLength, EFI_PAGE_SHIFT),
            (EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB)
            );
    }
  }
    
  DEBUG ((DEBUG_INFO, "HobSize - (0x%x)\n", (UINTN) PhitHob->EfiEndOfHobList - (UINTN) (*HobStart)));

  //
  // Relocate HOB List to an allocated pool buffer.
  // The relocation should be at after all the tested memory resources added
  // (except the memory space that covers HOB List) to the memory services,
  // because the memory resource found in CoreInitializeMemoryServices()
  // may have not enough remaining resource for HOB List.
  //
  NewHobList = AllocateCopyPool (
                 (UINTN) PhitHob->EfiEndOfHobList - (UINTN) (*HobStart),
                 *HobStart
                 );
  DEBUG ((DEBUG_INFO, "NewHob - 0x%x\n", NewHobList));
  ASSERT (NewHobList != NULL);

  *HobStart = NewHobList;
  gHobList  = NewHobList;
  
  BaseAddress = PageAlignAddress (PhitHob->EfiMemoryBottom);
  Length      = PageAlignLength  (PhitHob->EfiFreeMemoryBottom - PhitHob->EfiMemoryBottom);
  CoreAddMemoryDescriptor (
    EfiConventionalMemory,
    BaseAddress,
    RShiftU64 (Length, EFI_PAGE_SHIFT),
    (EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB)
    );

  return EFI_SUCCESS;
}
