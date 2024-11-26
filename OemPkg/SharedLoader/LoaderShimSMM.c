#include "LoaderShim.h"
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SmmServicesTableLib.h>

DRIVER_DEPENDENCIES *gDriverDependencies = NULL;

VOID
InstallDriverDependencies (
  EFI_SYSTEM_TABLE  SystemTable
  )
{

  gDriverDependencies->AllocatePages       = gSmst->SmmAllocatePages;
  gDriverDependencies->FreePages           = gSmst->SmmFreePages;
  gDriverDependencies->LocateProtocol      = gSmst->SmmLocateProtocol;
  gDriverDependencies->AllocatePool        = gSmst->SmmAllocatePool;
  gDriverDependencies->FreePool            = gSmst->SmmFreePool;
}

EFI_STATUS
EFIAPI
SmmEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies (*SystemTable);
  }

  Status = LoaderEntryPoint (ImageHandle, SystemTable);
  if (EFI_ERROR (Status)) {
    FreePool (gDriverDependencies);
  }

  return Status;
}
