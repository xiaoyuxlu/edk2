/** @file
  ELF loader

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#include <Base.h>
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <IndustryStandard/elf_common.h>
#include <IndustryStandard/elf32.h>
#include <IndustryStandard/elf64.h>

typedef struct {
  UINT32  Field;
  CHAR8   *Name;
} FIELD_NAME;

CHAR8 mTempStr[256];

CHAR8 *mEClassName[] = {
  "None",
  "32Bit",
  "64Bit",
};
CHAR8 *
ElfEClassToName (
  IN UINT8 EClass
  )
{
  if (EClass < ARRAY_SIZE(mEClassName)) {
    return mEClassName[EClass];
  } else {
    return "<Unknown>";
  }
}

CHAR8 *mEDataName[] = {
  "None",
  "LittleEndian",
  "BigEndian",
};
CHAR8 *
ElfEDataToName (
  IN UINT8 EData
  )
{
  if (EData < ARRAY_SIZE(mEDataName)) {
    return mEDataName[EData];
  } else {
    return "<Unknown>";
  }
}

CHAR8 *mEOSABIName[] = {
  "None",
  "HP-UX",
  "NetBSD",
  "GNU",
  "Linux",
  "Solaris",
  "AIX",
  "IRIX",
  "FreeBSD",
  "TRU64",
  "Modesto",
  "OpenBSD",
  "OpenVMS",
  "HP-NSK",
  "AROS",
  "FenixOS",
  "CloudABI",
  "OpenVOS",
};
CHAR8 *
ElfEOSABIToName (
  IN UINT8 EOSABI
  )
{
  if (EOSABI < ARRAY_SIZE(mEOSABIName)) {
    return mEOSABIName[EOSABI];
  } else {
    return "<Unknown>";
  }
}

CHAR8 *mETypeName[] = {
  "None",
  "Relocatable",
  "Executable",
  "SharedObject",
  "CoreFile",
};
CHAR8 *
ElfETypeToName (
  IN UINT16 EType
  )
{
  if (EType < ARRAY_SIZE(mETypeName)) {
    return mETypeName[EType];
  } else {
    return "<Unknown>";
  }
}

FIELD_NAME mEMachineFieldName[] = {
  {EM_386,     "i386"},
  {EM_X86_64,  "X86_64"},
  {EM_ARM,     "ARM"},
  {EM_AARCH64, "AARCH64"},
};
CHAR8 *
ElfEMachineToName (
  IN UINT16 EMachine
  )
{
  UINTN Index;
  for (Index = 0; Index < ARRAY_SIZE(mEMachineFieldName); Index++) {
    if (mEMachineFieldName[Index].Field == EMachine) {
      return mEMachineFieldName[Index].Name;
    }
  }
  return "<Unknown>";
}

CHAR8 *mShTypeName[] = {
  "None",
  "program",
  "symbol table",
  "string table",
  "relocation with addends",
  "symbol hash table",
  "dynamic",
  "note",
  "no space",
  "relocation no addends",
  "reserved",
  "dynamic symbol table",
  "reserved",
  "reserved",
  "Init Array",
  "Fini Array",
  "Pre-Init Array",
  "Section group",
  "Section indexes",
};
CHAR8 *
ElfShTypeToName (
  IN UINT32 ShType
  )
{
  if (ShType < ARRAY_SIZE(mShTypeName)) {
    return mShTypeName[ShType];
  } else {
    return "<Unknown>";
  }
}

CHAR8 *mShFlagName[] = {
  "WRITE",
  "ALLOC",
  "EXEC",
  "",
  "MERGE",
  "STRINGS",
  "INFO_LINK",
  "LINK_ORDER",
  "NONCONFORMING",
  "GROUP",
  "TLS",
};
CHAR8 *
ElfShFlagToName (
  IN UINT64 ShFlag
  )
{
  UINTN Index;
  mTempStr[0] = 0;
  for (Index = 0; Index < ARRAY_SIZE(mShFlagName); Index++) {
    if ((LShiftU64(1ull, Index) & ShFlag) != 0) {
      AsciiStrCatS (mTempStr, ARRAY_SIZE(mTempStr), mShFlagName[Index]);
      AsciiStrCatS (mTempStr, ARRAY_SIZE(mTempStr), ",");
    }
  }
  return mTempStr;
}

CHAR8 *mPTypeName[] = {
  "None",
  "Loadable segment",
  "Dynamic linking information",
  "Pathname of interpreter",
  "Auxiliary information",
  "Reserved",
  "Location of program header itself",
  "Thread local storage segment",
};
CHAR8 *
ElfPTypeToName (
  IN UINT32 PType
  )
{
  if (PType < ARRAY_SIZE(mPTypeName)) {
    return mPTypeName[PType];
  } else {
    return "<Unknown>";
  }
}

CHAR8 *mPFlagName[] = {
  "X",
  "W",
  "R",
};
CHAR8 *
ElfPFlagToName (
  IN UINT32 PFlag
  )
{
  UINTN Index;
  mTempStr[0] = 0;
  for (Index = 0; Index < ARRAY_SIZE(mPFlagName); Index++) {
    if (((1u << Index) & PFlag) != 0) {
      AsciiStrCatS (mTempStr, ARRAY_SIZE(mTempStr), mPFlagName[Index]);
      AsciiStrCatS (mTempStr, ARRAY_SIZE(mTempStr), ",");
    }
  }
  return mTempStr;
}

VOID
EFIAPI
DumpElf (
  IN VOID                            *ImageAddress
  )
{
  UINT8       EiClass;
  Elf32_Ehdr  *Ehdr32;
  Elf32_Shdr  *Shdr32;
  Elf32_Phdr  *Phdr32;
  Elf32_Shdr  *Name32;
  Elf64_Ehdr  *Ehdr64;
  Elf64_Shdr  *Shdr64;
  Elf64_Phdr  *Phdr64;
  Elf64_Shdr  *Name64;
  UINTN       Index;
  CHAR8       *Name;

  EiClass = ((UINT8 *)ImageAddress)[EI_CLASS];
  if (EiClass == ELFCLASS32) {
    // 32 bit
    Ehdr32 = ImageAddress;
    DEBUG ((DEBUG_INFO, "Ehdr32:\n"));
    DEBUG ((DEBUG_INFO, "  e_ident:\n"));
    Name = (CHAR8 *)&Ehdr32->e_ident[EI_MAG0];
    DEBUG ((DEBUG_INFO, "    Magic     - %08x (\'%c%c%c%c\')\n", *(UINT32 *)&Ehdr32->e_ident[EI_MAG0], Name[0], Name[1], Name[2], Name[3]));
    DEBUG ((DEBUG_INFO, "    Class     - %02x (%a)\n", *(UINT8 *)&Ehdr32->e_ident[EI_CLASS], ElfEClassToName(*(UINT8 *)&Ehdr32->e_ident[EI_CLASS])));
    DEBUG ((DEBUG_INFO, "    Data      - %02x (%a)\n", *(UINT8 *)&Ehdr32->e_ident[EI_DATA], ElfEDataToName(*(UINT8 *)&Ehdr32->e_ident[EI_DATA])));
    DEBUG ((DEBUG_INFO, "    Version   - %02x\n", *(UINT8 *)&Ehdr32->e_ident[EI_VERSION]));
    DEBUG ((DEBUG_INFO, "    OSABI     - %02x (%a)\n", *(UINT8 *)&Ehdr32->e_ident[EI_OSABI], ElfEOSABIToName(*(UINT8 *)&Ehdr32->e_ident[EI_OSABI])));
    DEBUG ((DEBUG_INFO, "    ABIVersion- %02x\n", *(UINT8 *)&Ehdr32->e_ident[EI_ABIVERSION]));
    DEBUG ((DEBUG_INFO, "    Size      - %02x\n", *(UINT8 *)&Ehdr32->e_ident[EI_NIDENT]));
    DEBUG ((DEBUG_INFO, "  e_type      - %04x (%a)\n", Ehdr32->e_type, ElfETypeToName(Ehdr32->e_type)));
    DEBUG ((DEBUG_INFO, "  e_machine   - %04x (%a)\n", Ehdr32->e_machine, ElfEMachineToName(Ehdr32->e_machine)));
    DEBUG ((DEBUG_INFO, "  e_version   - %08x\n", Ehdr32->e_version));
    DEBUG ((DEBUG_INFO, "  e_entry     - %08x\n", Ehdr32->e_entry));
    DEBUG ((DEBUG_INFO, "  e_phoff     - %08x\n", Ehdr32->e_phoff));
    DEBUG ((DEBUG_INFO, "  e_shoff     - %08x\n", Ehdr32->e_shoff));
    DEBUG ((DEBUG_INFO, "  e_flags     - %08x\n", Ehdr32->e_flags));
    DEBUG ((DEBUG_INFO, "  e_ehsize    - %04x\n", Ehdr32->e_ehsize));
    DEBUG ((DEBUG_INFO, "  e_phentsize - %04x\n", Ehdr32->e_phentsize));
    DEBUG ((DEBUG_INFO, "  e_phnum     - %04x\n", Ehdr32->e_phnum));
    DEBUG ((DEBUG_INFO, "  e_shentsize - %04x\n", Ehdr32->e_shentsize));
    DEBUG ((DEBUG_INFO, "  e_shnum     - %04x\n", Ehdr32->e_shnum));
    DEBUG ((DEBUG_INFO, "  e_shstrndx  - %04x\n", Ehdr32->e_shstrndx));

    Phdr32 = (VOID *)((UINTN)Ehdr32 + Ehdr32->e_phoff);
    Shdr32 = (VOID *)((UINTN)Ehdr32 + Ehdr32->e_shoff);
    Name32 = (VOID *)((UINTN)Shdr32 + Ehdr32->e_shstrndx * Ehdr32->e_shentsize);
    Name   = (VOID *)((UINTN)Ehdr32 + Name32->sh_offset);

    for (Index = 0; Index < Ehdr32->e_phnum; Index++) {
      DEBUG ((DEBUG_INFO, "Phdr32 (%d):\n", Index));
      DEBUG ((DEBUG_INFO, "  p_type      - %08x (%a)\n", Phdr32[Index].p_type, ElfPTypeToName(Phdr32[Index].p_type)));
      DEBUG ((DEBUG_INFO, "  p_flags     - %08x (%a)\n", Phdr32[Index].p_flags, ElfPFlagToName(Phdr32[Index].p_flags)));
      DEBUG ((DEBUG_INFO, "  p_offset    - %08x\n", Phdr32[Index].p_offset));
      DEBUG ((DEBUG_INFO, "  p_vaddr     - %08x\n", Phdr32[Index].p_vaddr));
      DEBUG ((DEBUG_INFO, "  p_paddr     - %08x\n", Phdr32[Index].p_paddr));
      DEBUG ((DEBUG_INFO, "  p_filesz    - %08x\n", Phdr32[Index].p_filesz));
      DEBUG ((DEBUG_INFO, "  p_memsz     - %08x\n", Phdr32[Index].p_memsz));
      DEBUG ((DEBUG_INFO, "  p_align     - %08x\n", Phdr32[Index].p_align));
    }
    for (Index = 0; Index < Ehdr32->e_shnum; Index++) {
      DEBUG ((DEBUG_INFO, "Shdr32 (%d):\n", Index));
      DEBUG ((DEBUG_INFO, "  sh_name     - %08x (%a)\n", Shdr32[Index].sh_name, Name + Shdr32[Index].sh_name));
      DEBUG ((DEBUG_INFO, "  sh_type     - %08x (%a)\n", Shdr32[Index].sh_type, ElfShTypeToName(Shdr32[Index].sh_type)));
      DEBUG ((DEBUG_INFO, "  sh_flags    - %08x (%a)\n", Shdr32[Index].sh_flags, ElfShFlagToName(Shdr32[Index].sh_flags)));
      DEBUG ((DEBUG_INFO, "  sh_addr     - %08x\n", Shdr32[Index].sh_addr));
      DEBUG ((DEBUG_INFO, "  sh_offset   - %08x\n", Shdr32[Index].sh_offset));
      DEBUG ((DEBUG_INFO, "  sh_size     - %08x\n", Shdr32[Index].sh_size));
      DEBUG ((DEBUG_INFO, "  sh_link     - %08x\n", Shdr32[Index].sh_link));
      DEBUG ((DEBUG_INFO, "  sh_info     - %08x\n", Shdr32[Index].sh_info));
      DEBUG ((DEBUG_INFO, "  sh_addralign- %08x\n", Shdr32[Index].sh_addralign));
      DEBUG ((DEBUG_INFO, "  sh_entsize  - %08x\n", Shdr32[Index].sh_entsize));
    }
  } else {
    // 64 bit
    Ehdr64 = ImageAddress;
    DEBUG ((DEBUG_INFO, "Ehdr64:\n"));
    DEBUG ((DEBUG_INFO, "  e_ident:\n"));
    Name = (CHAR8 *)&Ehdr64->e_ident[EI_MAG0];
    DEBUG ((DEBUG_INFO, "    Magic     - %08x (\'%c%c%c%c\')\n", *(UINT32 *)&Ehdr64->e_ident[EI_MAG0], Name[0], Name[1], Name[2], Name[3]));
    DEBUG ((DEBUG_INFO, "    Class     - %02x (%a)\n", *(UINT8 *)&Ehdr64->e_ident[EI_CLASS], ElfEClassToName(*(UINT8 *)&Ehdr64->e_ident[EI_CLASS])));
    DEBUG ((DEBUG_INFO, "    Data      - %02x (%a)\n", *(UINT8 *)&Ehdr64->e_ident[EI_DATA], ElfEDataToName(*(UINT8 *)&Ehdr64->e_ident[EI_DATA])));
    DEBUG ((DEBUG_INFO, "    Version   - %02x\n", *(UINT8 *)&Ehdr64->e_ident[EI_VERSION]));
    DEBUG ((DEBUG_INFO, "    OSABI     - %02x (%a)\n", *(UINT8 *)&Ehdr64->e_ident[EI_OSABI], ElfEOSABIToName(*(UINT8 *)&Ehdr64->e_ident[EI_OSABI])));
    DEBUG ((DEBUG_INFO, "    ABIVersion- %02x\n", *(UINT8 *)&Ehdr64->e_ident[EI_ABIVERSION]));
    DEBUG ((DEBUG_INFO, "    Size      - %02x\n", *(UINT8 *)&Ehdr64->e_ident[EI_NIDENT]));
    DEBUG ((DEBUG_INFO, "  e_type      - %04x (%a)\n", Ehdr64->e_type, ElfETypeToName(Ehdr64->e_type)));
    DEBUG ((DEBUG_INFO, "  e_machine   - %04x (%a)\n", Ehdr64->e_machine, ElfEMachineToName(Ehdr64->e_machine)));
    DEBUG ((DEBUG_INFO, "  e_version   - %08x\n", Ehdr64->e_version));
    DEBUG ((DEBUG_INFO, "  e_entry     - %016lx\n", Ehdr64->e_entry));
    DEBUG ((DEBUG_INFO, "  e_phoff     - %016lx\n", Ehdr64->e_phoff));
    DEBUG ((DEBUG_INFO, "  e_shoff     - %016lx\n", Ehdr64->e_shoff));
    DEBUG ((DEBUG_INFO, "  e_flags     - %08x\n", Ehdr64->e_flags));
    DEBUG ((DEBUG_INFO, "  e_ehsize    - %04x\n", Ehdr64->e_ehsize));
    DEBUG ((DEBUG_INFO, "  e_phentsize - %04x\n", Ehdr64->e_phentsize));
    DEBUG ((DEBUG_INFO, "  e_phnum     - %04x\n", Ehdr64->e_phnum));
    DEBUG ((DEBUG_INFO, "  e_shentsize - %04x\n", Ehdr64->e_shentsize));
    DEBUG ((DEBUG_INFO, "  e_shnum     - %04x\n", Ehdr64->e_shnum));
    DEBUG ((DEBUG_INFO, "  e_shstrndx  - %04x\n", Ehdr64->e_shstrndx));
    
    Phdr64 = (VOID *)((UINTN)Ehdr64 + (UINTN)Ehdr64->e_phoff);
    Shdr64 = (VOID *)((UINTN)Ehdr64 + (UINTN)Ehdr64->e_shoff);
    Name64 = (VOID *)((UINTN)Shdr64 + Ehdr64->e_shstrndx * Ehdr64->e_shentsize);
    Name   = (VOID *)((UINTN)Ehdr64 + (UINTN)Name64->sh_offset);

    for (Index = 0; Index < Ehdr64->e_phnum; Index++) {
      DEBUG ((DEBUG_INFO, "Phdr64 (%d):\n", Index));
      DEBUG ((DEBUG_INFO, "  p_type      - %08x (%a)\n", Phdr64[Index].p_type, ElfPTypeToName(Phdr64[Index].p_type)));
      DEBUG ((DEBUG_INFO, "  p_flags     - %08x (%a)\n", Phdr64[Index].p_flags, ElfPFlagToName(Phdr64[Index].p_flags)));
      DEBUG ((DEBUG_INFO, "  p_offset    - %016lx\n", Phdr64[Index].p_offset));
      DEBUG ((DEBUG_INFO, "  p_vaddr     - %016lx\n", Phdr64[Index].p_vaddr));
      DEBUG ((DEBUG_INFO, "  p_paddr     - %016lx\n", Phdr64[Index].p_paddr));
      DEBUG ((DEBUG_INFO, "  p_filesz    - %016lx\n", Phdr64[Index].p_filesz));
      DEBUG ((DEBUG_INFO, "  p_memsz     - %016lx\n", Phdr64[Index].p_memsz));
      DEBUG ((DEBUG_INFO, "  p_align     - %016lx\n", Phdr64[Index].p_align));
    }
    for (Index = 0; Index < Ehdr64->e_shnum; Index++) {
      DEBUG ((DEBUG_INFO, "Shdr64 (%d):\n", Index));
      DEBUG ((DEBUG_INFO, "  sh_name     - %08x (%a)\n", Shdr64[Index].sh_name, Name + Shdr64[Index].sh_name));
      DEBUG ((DEBUG_INFO, "  sh_type     - %08x (%a)\n", Shdr64[Index].sh_type, ElfShTypeToName(Shdr64[Index].sh_type)));
      DEBUG ((DEBUG_INFO, "  sh_flags    - %016lx (%a)\n", Shdr64[Index].sh_flags, ElfShFlagToName(Shdr64[Index].sh_flags)));
      DEBUG ((DEBUG_INFO, "  sh_addr     - %016lx\n", Shdr64[Index].sh_addr));
      DEBUG ((DEBUG_INFO, "  sh_offset   - %016lx\n", Shdr64[Index].sh_offset));
      DEBUG ((DEBUG_INFO, "  sh_size     - %016lx\n", Shdr64[Index].sh_size));
      DEBUG ((DEBUG_INFO, "  sh_link     - %08x\n", Shdr64[Index].sh_link));
      DEBUG ((DEBUG_INFO, "  sh_info     - %08x\n", Shdr64[Index].sh_info));
      DEBUG ((DEBUG_INFO, "  sh_addralign- %016lx\n", Shdr64[Index].sh_addralign));
      DEBUG ((DEBUG_INFO, "  sh_entsize  - %016lx\n", Shdr64[Index].sh_entsize));
    }
  }

  return ;
}

EFI_STATUS
EFIAPI
GetElfImageInfo (
  IN VOID                 *ImageAddress,
  IN UINTN                ImageSize,
  OUT VOID                **LoadedImageBase,
  OUT UINTN               *LoadedImageSize,
  OUT UINTN               *Entrypoint
  )
{
  UINT8       EiClass;
  Elf32_Ehdr  *Ehdr32;
  Elf32_Shdr  *Shdr32;
  Elf32_Phdr  *Phdr32;
  Elf64_Ehdr  *Ehdr64;
  Elf64_Shdr  *Shdr64;
  Elf64_Phdr  *Phdr64;
  UINTN       Index;
  UINTN       Bottom;
  UINTN       Top;

  Bottom = (UINTN)-1;
  Top = 0;

  EiClass = ((UINT8 *)ImageAddress)[EI_CLASS];
  if (EiClass == ELFCLASS32) {
    // 32 bit
    Ehdr32 = ImageAddress;
    Phdr32 = (VOID *)((UINTN)Ehdr32 + Ehdr32->e_phoff);
    Shdr32 = (VOID *)((UINTN)Ehdr32 + Ehdr32->e_shoff);
    
    for (Index = 0; Index < Ehdr32->e_phnum; Index++) {
      if (Phdr32[Index].p_type != PT_LOAD) {
        continue;
      }
      if (Bottom > Phdr32[Index].p_vaddr) {
        Bottom = Phdr32[Index].p_vaddr;
      }
      if (Top < Phdr32[Index].p_vaddr + Phdr32[Index].p_memsz) {
        Top = Phdr32[Index].p_vaddr + Phdr32[Index].p_memsz;
      }
    }
    *Entrypoint = (UINTN)Ehdr32->e_entry;
  } else {
    // 64 bit
    Ehdr64 = ImageAddress;
    Phdr64 = (VOID *)((UINTN)Ehdr64 + (UINTN)Ehdr64->e_phoff);
    Shdr64 = (VOID *)((UINTN)Ehdr64 + (UINTN)Ehdr64->e_shoff);

    for (Index = 0; Index < Ehdr64->e_phnum; Index++) {
      if (Phdr64[Index].p_type != PT_LOAD) {
        continue;
      }
      if (Bottom > Phdr64[Index].p_vaddr) {
        Bottom = Phdr64[Index].p_vaddr;
      }
      if (Top < Phdr64[Index].p_vaddr + Phdr64[Index].p_memsz) {
        Top = Phdr64[Index].p_vaddr + Phdr64[Index].p_memsz;
      }
    }
    *Entrypoint = (UINTN)Ehdr64->e_entry;
  }
  Bottom = Bottom & ~(SIZE_4KB - 1);
  Top = ALIGN_VALUE(Top, SIZE_4KB);

  *LoadedImageBase = (VOID *)Bottom;
  *LoadedImageSize = (Top - Bottom);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LoadElfImageData (
  IN VOID                 *RawImageBase,
  IN UINTN                RawImageSize,
  IN VOID                 *LoadedImageBase,
  IN UINTN                LoadedImageSize,
  OUT UINTN               *Entrypoint
  )
{
  UINT8                                EiClass;
  Elf32_Ehdr                           *Ehdr32;
  Elf32_Shdr                           *Shdr32;
  Elf32_Phdr                           *Phdr32;
  Elf64_Ehdr                           *Ehdr64;
  Elf64_Shdr                           *Shdr64;
  Elf64_Phdr                           *Phdr64;
  UINTN                                Index;

  //
  // 1. Load per program header.
  //
  EiClass = ((UINT8 *)RawImageBase)[EI_CLASS];
  if (EiClass == ELFCLASS32) {
    // 32 bit
    Ehdr32 = RawImageBase;
    Phdr32 = (VOID *)((UINTN)Ehdr32 + Ehdr32->e_phoff);
    Shdr32 = (VOID *)((UINTN)Ehdr32 + Ehdr32->e_shoff);
    
    for (Index = 0; Index < Ehdr32->e_phnum; Index++) {
      if (Phdr32[Index].p_type != PT_LOAD) {
        continue;
      }
      ASSERT ((UINTN)LoadedImageBase <= (UINTN)Phdr32[Index].p_vaddr);
      ASSERT ((UINTN)LoadedImageBase + LoadedImageSize >= (UINTN)Phdr32[Index].p_vaddr + Phdr32[Index].p_filesz);
      CopyMem (
        (UINT8 *)(UINTN)Phdr32[Index].p_vaddr,
        (UINT8 *)RawImageBase + Phdr32[Index].p_offset,
        Phdr32[Index].p_filesz
        );
    }
    *Entrypoint = (UINTN)Ehdr32->e_entry;
  } else {
    // 64 bit
    Ehdr64 = RawImageBase;
    Phdr64 = (VOID *)((UINTN)Ehdr64 + (UINTN)Ehdr64->e_phoff);
    Shdr64 = (VOID *)((UINTN)Ehdr64 + (UINTN)Ehdr64->e_shoff);
    
    for (Index = 0; Index < Ehdr64->e_phnum; Index++) {
      if (Phdr64[Index].p_type != PT_LOAD) {
        continue;
      }
      ASSERT ((UINTN)LoadedImageBase <= (UINTN)Phdr64[Index].p_vaddr);
      ASSERT ((UINTN)LoadedImageBase + LoadedImageSize >= (UINTN)Phdr64[Index].p_vaddr + Phdr64[Index].p_filesz);
      CopyMem (
        (UINT8 *)(UINTN)Phdr64[Index].p_vaddr,
        (UINT8 *)RawImageBase + (UINTN)Phdr64[Index].p_offset,
        (UINTN)Phdr64[Index].p_filesz
        );
    }
    *Entrypoint = (UINTN)Ehdr64->e_entry;
  }

  return EFI_SUCCESS;
}
