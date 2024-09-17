#include <Uefi.h>
#include <PiDxe.h>

#include <Library/PeCoffLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/PeCoffGetEntryPointLib.h>

#include "Common/Common.h"
#include "SharedLoaderPeCoffLib.h"

EFI_STATUS
EFIAPI
LoaderEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  VOID        *ImageBase;
  VOID        *SectionData;
  UINTN       SectionSize;

  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  EFI_IMAGE_EXPORT_DIRECTORY    *Exports;

  // First we must walk all the FV's and find the one that contains the shared library
  EFI_GUID CommonGuid = COMMON_GUID;

  //
  // Print out the GUID of the shared library
  //
  DEBUG ((DEBUG_INFO, "Searching for Shared library GUID: %g\n", &CommonGuid));

  //
  // Get the section data from any FV that contains the shared library
  //
  Status = GetSectionFromAnyFv (&CommonGuid, EFI_SECTION_PE32, 0, &SectionData, &SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find section with known GUID: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "Found section with known GUID, size: %u bytes\n", SectionSize));

  // Next we will load the shared library into memory
  // we'll use PeCoffLoaderGetImageInfo to get the image size

  ZeroMem (&ImageContext, sizeof (ImageContext));

  ImageContext.Handle    = SectionData;
  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;

  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get image info: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "Image size: %u bytes\n", ImageContext.ImageSize));

  // then we'll allocate memory for the image

  ImageBase = AllocatePool ((UINTN)ImageContext.ImageSize);
  if (ImageBase == NULL) {
    DEBUG ((DEBUG_ERROR, "Failed to allocate memory for image\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  ImageContext.ImageAddress = (EFI_PHYSICAL_ADDRESS)ImageBase;

  // then we'll load the image into memory

  Status = PeCoffLoaderLoadImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load image: %r\n", Status));
    goto Exit;
  }

  // then we'll relocate the image

  Status = PeCoffLoaderRelocateImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to relocate image: %r\n", Status));
    goto Exit;
  }

  Status = GetExportDirectoryInPeCoffImage(ImageBase, &ImageContext, &Exports);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get export directory: %r\n", Status));
    goto Exit;
  }

  DUMP_HEX (DEBUG_INFO, 0, (VOID *)Exports, sizeof (Exports), "");


  // then we'll call the entry point

  // TODO - call the entry point

  // use PeCoffLoaderGetEntryPoint to locate the entry point of the shared library

  // then we will call the entry point and pass in the IMPORTS structure

  // the shared library will return the EXPORTS structure

  Status = EFI_SUCCESS;

Exit:
  if (ImageBase != NULL) {
    FreePool (ImageBase);
  }

  DEBUG ((DEBUG_INFO, "Exiting with status: %r\n", Status));

  return Status;
}

EFI_STATUS
EFIAPI
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return LoaderEntryPoint (ImageHandle, SystemTable);
}

EFI_STATUS
EFIAPI
SmmEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return LoaderEntryPoint (ImageHandle, SystemTable);
}

/**
  The user Entry Point for Application. This code is only meant for
  testing the shared library loading functionality.

  @param[in] ImageHandle        The firmware allocated handle for the EFI image.
  @param[in] SystemTable        A pointer to the EFI System Table.

  @retval EFI_SUCCESS           The entry point is executed successfully.
  @retval EFI_INVALID_PARAMETER SystemTable provided was not valid.
  @retval other                 Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
AppEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return LoaderEntryPoint (ImageHandle, SystemTable);
}
