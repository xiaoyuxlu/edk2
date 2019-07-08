/** @file
  ELF loader

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __ELF_LOADER_LIB__
#define __ELF_LOADER_LIB__

#include <IndustryStandard/elf_common.h>
#include <IndustryStandard/elf32.h>
#include <IndustryStandard/elf64.h>

VOID
EFIAPI
DumpElf (
  IN VOID                            *ImageAddress
  );

EFI_STATUS
EFIAPI
GetElfImageInfo (
  IN VOID                 *ImageAddress,
  IN UINTN                ImageSize,
  OUT VOID                **LoadedImageBase,
  OUT UINTN               *LoadedImageSize,
  OUT UINTN               *Entrypoint
  );

EFI_STATUS
EFIAPI
LoadElfImageData (
  IN VOID                 *RawImageBase,
  IN UINTN                RawImageSize,
  IN VOID                 *LoadedImageBase,
  IN UINTN                LoadedImageSize,
  OUT UINTN               *Entrypoint
  );

#endif
