#include <Uefi.h>
#include <PiDxe.h>

#include <Library/PeCoffLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/PeCoffGetEntryPointLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DxeServicesTableLib.h>

#include <Protocol/MemoryAttribute.h>

#include "HelloUefiLib/SharedDependencies.h"
#include "SharedLoaderPeCoffLib.h"

typedef struct _INTERNAL_IMAGE_CONTEXT {
  //
  // Size of the Image in Bytes
  //
  UINTN                           Size;
  //
  // Number of Pages required
  //
  UINTN                           NumberOfPages;
  //
  // The allocated memory base
  // this may or may not align to the image start
  //
  EFI_PHYSICAL_ADDRESS            PageBase;
  //
  // The image context required by PeCoff functions
  //
  PE_COFF_LOADER_IMAGE_CONTEXT    Context;
} INTERNAL_IMAGE_CONTEXT;

VOID
SetupDependencies (
  DEPENDENCIES  *Depends
  )
{
  //
  // First declare this structure is a Dependency structure
  //
  Depends->Signature = DEPENDS_SIGNATURE;

  //
  // Now we must agree on the version of the structure
  //
  Depends->Version = DEPENDS_VERSION;

  //
  // Start filling in the dependencies requested
  //
  Depends->DebugPrint = DebugPrint;

  //
  //
  //
}

EFI_STATUS
EFIAPI
LoaderEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  VOID        *SectionData;
  UINTN       SectionSize;
  UINT32      RVA;
  EFI_GUID    CommonGuid = SHARED_FILE_GUID;

  INTERNAL_IMAGE_CONTEXT         Image;
  EFI_IMAGE_EXPORT_DIRECTORY     *Exports;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL  *MemoryAttribute;
  CONSTRUCTOR                    Constructor;
  DEPENDENCIES                   Depends;

  // First we must walk all the FV's and find the one that contains the shared library

  Status = SystemTable->BootServices->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&MemoryAttribute);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to locate Memory Attribute Protocol: %r\n", Status));
    //
    // Potentially the platform doesn't have this protocol / doesn't set memory protections. So we can't error out.
    // However we need to be careful
    //
    MemoryAttribute = NULL;
  }

  ZeroMem (&Image, sizeof (Image));

  //
  // Print out the GUID of the shared library
  //
  DEBUG ((DEBUG_INFO, "Searching for Shared library GUID: %g\n", CommonGuid));

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

  Image.Context.Handle    = SectionData;
  Image.Context.ImageRead = PeCoffLoaderImageReadFromMemory;
  Status                  = PeCoffLoaderGetImageInfo (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get image info: %r\n", Status));
    return Status;
  }

  //
  // Confirm that the image is an EFI application
  //
  if ((Image.Context.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION)) {
    DEBUG ((DEBUG_ERROR, "Invalid image type: %d\n", Image.Context.ImageType));
    return EFI_UNSUPPORTED;
  }

  //
  // Set the correct memory types for the image
  //
  Image.Context.ImageCodeMemoryType = EfiLoaderCode;
  Image.Context.ImageDataMemoryType = EfiLoaderData;

  //
  // Calculate the number of pages needed to load the image
  //
  if (Image.Context.SectionAlignment > EFI_PAGE_SIZE) {
    Image.Size = (UINTN)Image.Context.ImageSize + Image.Context.SectionAlignment;
  } else {
    Image.Size = (UINTN)Image.Context.ImageSize;
  }

  //
  // Calculate the number of pages needed to load the image
  //
  Image.NumberOfPages = EFI_SIZE_TO_PAGES (Image.Size);

  DEBUG ((DEBUG_INFO, "Image size: %u bytes\n", Image.Size));
  DEBUG ((DEBUG_INFO, "Number of pages: %u\n", Image.NumberOfPages));

  //
  // Allocate Executable memory for the image
  //
  Status = SystemTable->BootServices->AllocatePages (
                                        AllocateAnyPages,
                                        (EFI_MEMORY_TYPE)(Image.Context.ImageCodeMemoryType),
                                        Image.NumberOfPages,
                                        &Image.PageBase
                                        );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to allocate memory for image: %r\n", Status));
    return Status;
  }

  //
  // Since we're going to align the buffer on a section boundary, we need to save the original address
  // Set the image address to the base of the allocated memory
  //
  Image.Context.ImageAddress = (EFI_PHYSICAL_ADDRESS)Image.PageBase;

  if (MemoryAttribute != NULL) {
    UINT64  Attributes;

    DEBUG ((DEBUG_INFO, "Using Memory Attributes Protocol to clear XP"));

    Status = MemoryAttribute->GetMemoryAttributes (MemoryAttribute, Image.PageBase, Image.Size, &Attributes);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to retrieve memory attributes"));
      goto Exit;
    }

    //
    // Print out the attributes
    //
    DEBUG ((DEBUG_INFO, "Memory Attributes: 0x%x\n", Attributes));
    DEBUG ((DEBUG_INFO, "XP Memory: %a\n", (Attributes & EFI_MEMORY_XP) ? "Yes" : "No"));

    Status = MemoryAttribute->ClearMemoryAttributes (
                                MemoryAttribute,
                                Image.PageBase,
                                Image.Size,
                                EFI_MEMORY_XP
                                );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to clear EFI_MEMORY_XP (%r) \n", Status));
      ASSERT (FALSE);
    }
  } else {
    //
    // Try to use the DXE Services protocol to set the memory attributes
    //
    EFI_GCD_MEMORY_SPACE_DESCRIPTOR  MemDesc;

    DEBUG ((DEBUG_INFO, "%a:%d\n", __FILE__, __LINE__));

    //
    // Make sure that the buffer can be used to store code.
    //
    Status = gDS->GetMemorySpaceDescriptor (Image.Context.ImageAddress, &MemDesc);
    ASSERT_EFI_ERROR (Status);

    // Print out the memory attributes
    //
    DEBUG ((DEBUG_INFO, "Memory Attributes: 0x%x\n", MemDesc.Attributes));
    DEBUG ((DEBUG_INFO, "XP Memory: %a\n", (MemDesc.Attributes & EFI_MEMORY_XP) ? "Yes" : "No"));

    if ((MemDesc.Attributes & EFI_MEMORY_XP) == 0) {
      DEBUG ((DEBUG_ERROR, "Memory is not executable\n"));

      //
      // Nothing we can do - lets just try not to crash.
      //
      goto Exit;
      // TODO
    }
  }

  //
  // Align buffer on section boundary
  //
  Image.Context.ImageAddress += Image.Context.SectionAlignment - 1;
  Image.Context.ImageAddress &= ~((EFI_PHYSICAL_ADDRESS)Image.Context.SectionAlignment - 1);

  DEBUG ((DEBUG_INFO, "Allocated memory at 0x%x\n", Image.Context.ImageAddress));

  //
  // Load the image into the allocated memory
  //
  Status = PeCoffLoaderLoadImage (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load image: %r\n", Status));
    goto Exit;
  }

  //
  // Relocate the image in memory
  //
  Status = PeCoffLoaderRelocateImage (&Image.Context);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to relocate image: %r\n", Status));
    goto Exit;
  }

  //
  // Grab the export directory from the image
  //
  Status = GetExportDirectoryInPeCoffImage ((VOID *)Image.Context.ImageAddress, &Image.Context, &Exports);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to get export directory: %r\n", Status));
    goto Exit;
  }

  DEBUG_CODE_BEGIN ();

  //
  // Assuming we have the export directory, print out the exported functions
  //
  PrintExportedFunctions ((VOID *)Image.Context.ImageAddress, Exports);

  DEBUG_CODE_END ();

  //
  // Find the constructor function
  //
  Status = FindExportedFunction ((VOID *)Image.Context.ImageAddress, Exports, CONSTRUCTOR_NAME, &RVA);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find exported function: %r\n", Status));
    goto Exit;
  }

  SetupDependencies (&Depends);

  //
  // Setup the Library constructor function
  //
  Constructor = (CONSTRUCTOR)((EFI_PHYSICAL_ADDRESS)Image.Context.ImageAddress + RVA);

  InvalidateInstructionCacheRange ((VOID *)(UINTN)Image.Context.ImageAddress, (UINTN)Image.Context.ImageSize);
  Status = Constructor (&Depends);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to call LibConstructor: %r\n", Status));
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:
  if (Image.Context.ImageAddress != 0) {
    SystemTable->BootServices->FreePages (Image.PageBase, Image.NumberOfPages);
  }

  if (SectionData != NULL) {
    FreePool (SectionData);
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
