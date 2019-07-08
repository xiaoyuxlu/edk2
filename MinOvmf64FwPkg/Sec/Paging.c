/** @file

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiCpuLib.h>

#define IA32_PG_P                   BIT0
#define IA32_PG_RW                  BIT1
#define IA32_PG_U                   BIT2
#define IA32_PG_PS                  BIT7
#define IA32_PG_NX                  BIT63

UINTN
CreateHostPaging (
  VOID
  )
{
  UINTN                             PageTable;
  UINTN                             Index;
  UINTN                             SubIndex;
  UINTN                             Pml4Index;
  UINT64                            *Pde;
  UINT64                            *Pte;
  UINT64                            *Pml4;
  UINT64                            BaseAddress;
  UINTN                             NumberOfPml4EntriesNeeded;
  UINTN                             NumberOfPdpEntriesNeeded;
  UINT32                            RegEax;
  UINT32                            RegEdx;
  UINT8                             PhysicalAddressBits;
  UINT64                            MaximumSupportAddress;
  BOOLEAN                           Is1GPageSupport;
  UINTN                             PageTableAddress;

  PageTableAddress = PcdGet32 (PcdOvmfSecPeiTempRamBase) + PcdGet32 (PcdOvmfSecPeiTempRamSize);

  Is1GPageSupport = FALSE;
  AsmCpuid (0x80000000, &RegEax, NULL, NULL, NULL);
  if (RegEax >= 0x80000001) {
    AsmCpuid (0x80000001, NULL, NULL, NULL, &RegEdx);
    if ((RegEdx & BIT26) != 0) {
      Is1GPageSupport = TRUE;
    }
  }
  DEBUG((DEBUG_INFO, "CPUID - Is1GPageSupport - %x\n", Is1GPageSupport));
  
  AsmCpuid(0x80000000, &RegEax, NULL, NULL, NULL);
  if (RegEax >= 0x80000008) {
    AsmCpuid(0x80000008, &RegEax, NULL, NULL, NULL);
    RegEax = (UINT8)RegEax;
  } else {
    RegEax = 36;
  }
  PhysicalAddressBits = (UINT8)RegEax;
  DEBUG((DEBUG_INFO, "CPUID - PhysicalAddressBits - %d\n", (UINT8)RegEax));

  //BUGBUG: Too slow
  PhysicalAddressBits = 36;

  //
  // we dont support 5 level paging.
  //
  if (PhysicalAddressBits > 48) {
    PhysicalAddressBits = 48;
  }
  MaximumSupportAddress = (LShiftU64(1, PhysicalAddressBits) - 1);

  //
  // Allocate new page table, because we need set NX flag.
  //
  PageTable = (UINTN)PageTableAddress;
  PageTableAddress += SIZE_4KB;
  Pml4 = (UINT64 *)PageTable;

  if (PhysicalAddressBits <= 39) {
    NumberOfPml4EntriesNeeded = 1;
    NumberOfPdpEntriesNeeded = (UINTN)LShiftU64 (1, PhysicalAddressBits - 30);
  } else {
    NumberOfPml4EntriesNeeded = (UINTN)LShiftU64 (1, PhysicalAddressBits - 39);
    NumberOfPdpEntriesNeeded = 512;
  }

  BaseAddress = 0;
  for (Pml4Index = 0; Pml4Index < NumberOfPml4EntriesNeeded; Pml4Index++) {
    Pde = (UINT64 *)(UINTN)PageTableAddress;
    PageTableAddress += SIZE_4KB;
    Pml4[Pml4Index] = (UINT64)(UINTN)Pde | IA32_PG_RW | IA32_PG_P;

    if (Is1GPageSupport) {
      for (Index = 0; Index < NumberOfPdpEntriesNeeded; Index++) {
        Pde[Index] = (UINT64)(UINTN)BaseAddress | IA32_PG_PS | IA32_PG_RW | IA32_PG_P;
        BaseAddress += SIZE_1GB;
      }
    } else {
      for (Index = 0; Index < NumberOfPdpEntriesNeeded; Index++) {
        Pte = (UINT64 *)(UINTN)PageTableAddress;
        PageTableAddress += SIZE_4KB;
        Pde[Index] = (UINT64)(UINTN)Pte | IA32_PG_RW | IA32_PG_P;
        for (SubIndex = 0; SubIndex < SIZE_4KB / sizeof(*Pte); SubIndex++) {
          Pte[SubIndex] = BaseAddress | IA32_PG_PS | IA32_PG_RW | IA32_PG_P;
          BaseAddress += SIZE_2MB;
        }
      }
    }
  }

  DEBUG ((DEBUG_INFO, "FinalAddress - 0x%lx\n", BaseAddress));
  DEBUG ((DEBUG_INFO, "PageTable - 0x%lx\n", PageTable));
  AsmWriteCr3 (PageTable);
  DEBUG ((DEBUG_INFO, "Cr3 - 0x%x\n", AsmReadCr3()));

  return (PageTableAddress - PageTable);
}
