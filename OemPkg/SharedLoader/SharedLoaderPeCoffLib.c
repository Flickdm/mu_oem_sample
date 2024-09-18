/** @file

  The PRM Module Discovery library provides functionality to discover PRM modules installed by platform firmware.

  Copyright (c) Microsoft Corporation
  Copyright (c) 2020 - 2022, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Uefi.h"
#include <Library/DebugLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "SharedLoaderPeCoffLib.h"

// https://github.com/tianocore/edk2/blob/670e263419eb875fd8dce0c8d18dd3ab02b83ba0/PrmPkg/Library/DxePrmModuleDiscoveryLib/DxePrmModuleDiscoveryLib.c#L270


EFI_STATUS
GetExportDirectoryInPeCoffImage (
  IN  VOID                          *Image,
  IN  PE_COFF_LOADER_IMAGE_CONTEXT  *PeCoffLoaderImageContext,
  OUT EFI_IMAGE_EXPORT_DIRECTORY    **ImageExportDirectory
  )
{
  UINT16                               Magic;
  UINT32                               NumberOfRvaAndSizes;
  EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  OptionalHeaderPtrUnion;
  EFI_IMAGE_DATA_DIRECTORY             *DirectoryEntry;
  EFI_IMAGE_EXPORT_DIRECTORY           *ExportDirectory;

  if ((Image == NULL) || (PeCoffLoaderImageContext == NULL) || (ImageExportDirectory == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  DirectoryEntry  = NULL;
  ExportDirectory = NULL;

  //
  // NOTE: For backward compatibility, use the Machine field to identify a PE32/PE32+
  //       image instead of using the Magic field. Some systems might generate a PE32+
  //       image with PE32 magic.
  //
  switch (PeCoffLoaderImageContext->Machine) {
    case EFI_IMAGE_MACHINE_IA32:
      //
      // Assume PE32 image with IA32 Machine field.
      //
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
      break;
    case EFI_IMAGE_MACHINE_X64:
    case EFI_IMAGE_MACHINE_AARCH64:
      //
      // Assume PE32+ image with X64 Machine field
      //
      Magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
      break;
    default:
      //
      // For unknown Machine field, use Magic in optional header
      //
      DEBUG ((DEBUG_WARN, "%a: The machine type for this image is not valid for a PRM module.\n", __FUNCTION__));
      return EFI_UNSUPPORTED;
  }

  OptionalHeaderPtrUnion.Pe32 = (EFI_IMAGE_NT_HEADERS32 *)(
                                                           (UINTN)Image +
                                                           PeCoffLoaderImageContext->PeCoffHeaderOffset
                                                           );

  //
  // Check the PE/COFF Header Signature. Determine if the image is valid and/or a TE image.
  //
  if (OptionalHeaderPtrUnion.Pe32->Signature != EFI_IMAGE_NT_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "%a: The PE signature is not valid for the current image.\n", __FUNCTION__));
    return EFI_UNSUPPORTED;
  }

  if (Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    //
    // Use the PE32 offset to get the Export Directory Entry
    //
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT]);
  } else if (OptionalHeaderPtrUnion.Pe32->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    //
    // Use the PE32+ offset get the Export Directory Entry
    //
    NumberOfRvaAndSizes = OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.NumberOfRvaAndSizes;
    DirectoryEntry      = (EFI_IMAGE_DATA_DIRECTORY *)&(OptionalHeaderPtrUnion.Pe32Plus->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT]);
  } else {
    return EFI_UNSUPPORTED;
  }

  if ((NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY_EXPORT) || (DirectoryEntry->VirtualAddress == 0)) {
    //
    // The export directory is not present
    //
    return EFI_NOT_FOUND;
  } else if (((UINT32)(~0) - DirectoryEntry->VirtualAddress) < DirectoryEntry->Size) {
    //
    // The directory address overflows
    //
    DEBUG ((DEBUG_ERROR, "%a: The export directory entry in this image results in overflow.\n", __FUNCTION__));
    return EFI_UNSUPPORTED;
  } else {
    DEBUG ((DEBUG_INFO, "%a: Export Directory Entry found in the image at 0x%x.\n", __FUNCTION__, (UINTN)OptionalHeaderPtrUnion.Pe32));
    DEBUG ((DEBUG_INFO, "  %a: Directory Entry Virtual Address = 0x%x.\n", __FUNCTION__, DirectoryEntry->VirtualAddress));

    ExportDirectory = (EFI_IMAGE_EXPORT_DIRECTORY *)((UINTN)Image + DirectoryEntry->VirtualAddress);
    DEBUG ((
      DEBUG_INFO,
      "  %a: Export Directory Table found successfully at 0x%x. Name address = 0x%x. Name = %a.\n",
      __FUNCTION__,
      (UINTN)ExportDirectory,
      ((UINTN)Image + ExportDirectory->Name),
      (CHAR8 *)((UINTN)Image + ExportDirectory->Name)
      ));
  }

  *ImageExportDirectory = ExportDirectory;

  return EFI_SUCCESS;
}

VOID
PrintExportedFunctions (
  IN VOID                        *Image,
  IN EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory
  )
{
  UINT32  *AddressOfNames;
  CHAR8   *FunctionName;
  UINT32  Index;

  if ((Image == NULL) || (ExportDirectory == NULL)) {
    DEBUG ((DEBUG_ERROR, "%a: Invalid parameter.\n", __FUNCTION__));
    return;
  }

  AddressOfNames = (UINT32 *)((UINTN)Image + ExportDirectory->AddressOfNames);

  DEBUG ((DEBUG_INFO, "Exported Functions:\n"));
  for (Index = 0; Index < ExportDirectory->NumberOfNames; Index++) {
    FunctionName = (CHAR8 *)((UINTN)Image + AddressOfNames[Index]);
    DEBUG ((DEBUG_INFO, "  %a\n", FunctionName));
  }
}

EFI_STATUS
FindExportedFunction (
  IN  VOID                        *Image,
  IN  EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory,
  IN  CHAR8                       *FunctionName,
  OUT UINT32                      *FunctionAddress
  )
{
  UINT32  *AddressOfNames;
  UINT16  *AddressOfNameOrdinals;
  UINT32  *AddressOfFunctions;
  CHAR8   *CurrentFunctionName;
  UINT32  Index;

  if ((Image == NULL) || (ExportDirectory == NULL) || (FunctionName == NULL) || (FunctionAddress == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  AddressOfNames = (UINT32 *)((UINTN)Image + ExportDirectory->AddressOfNames);
  AddressOfNameOrdinals = (UINT16 *)((UINTN)Image + ExportDirectory->AddressOfNameOrdinals);
  AddressOfFunctions = (UINT32 *)((UINTN)Image + ExportDirectory->AddressOfFunctions);

  for (Index = 0; Index < ExportDirectory->NumberOfNames; Index++) {
    CurrentFunctionName = (CHAR8 *)((UINTN)Image + AddressOfNames[Index]);
    if (AsciiStrCmp(CurrentFunctionName, FunctionName) == 0) {
      *FunctionAddress = AddressOfFunctions[AddressOfNameOrdinals[Index]];
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
GetFunctionAddress (
  IN  VOID   *Image,
  IN  CHAR8  *FunctionName,
  OUT VOID   **FunctionAddress
  )
{
  EFI_STATUS                    Status;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  EFI_IMAGE_EXPORT_DIRECTORY    *ExportDirectory;
  UINT32                        FunctionRva;

  if ((Image == NULL) || (FunctionName == NULL) || (FunctionAddress == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem(&ImageContext, sizeof(ImageContext));
  ImageContext.ImageAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)Image;

  Status = PeCoffLoaderGetImageInfo(&ImageContext);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = GetExportDirectoryInPeCoffImage(Image, &ImageContext, &ExportDirectory);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  Status = FindExportedFunction(Image, ExportDirectory, FunctionName, &FunctionRva);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  *FunctionAddress = (VOID *)((UINTN)Image + FunctionRva);
  return EFI_SUCCESS;
}