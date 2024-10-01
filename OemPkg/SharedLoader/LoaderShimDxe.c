#include "LoaderShim.h"
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DxeServicesLib.h>

#include "HelloUefiLib/SharedDependencies.h"

DRIVER_DEPENDENCIES  *gDriverDependencies = NULL;

VOID
InstallDriverDependencies (
  EFI_SYSTEM_TABLE  SystemTable
  )
{
  gDriverDependencies->AllocatePages  = SystemTable.BootServices->AllocatePages;
  gDriverDependencies->FreePages      = SystemTable.BootServices->FreePages;
  gDriverDependencies->LocateProtocol = SystemTable.BootServices->LocateProtocol;
  gDriverDependencies->AllocatePool   = SystemTable.BootServices->AllocatePool;
  gDriverDependencies->FreePool       = SystemTable.BootServices->FreePool;
}

EFI_STATUS
EFIAPI
DxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_GUID    CommonGuid = SHARED_FILE_GUID;
  EFI_STATUS  Status;
  VOID        *SectionData;
  UINTN       SectionSize;

  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies (*SystemTable);
  }

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

  Status = LoaderEntryPoint (SectionData, SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to load shared library: %r\n", Status));
    goto Exit;
  }

  Status = EFI_SUCCESS;

Exit:

  if (gDriverDependencies != NULL) {
    FreePool (gDriverDependencies);
  }

  if (SectionData != NULL) {
    FreePool (SectionData);
  }

  return Status;
}
