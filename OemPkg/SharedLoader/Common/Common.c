#include <uefi.h>

#include "Common.h"

IMPORTS  mImports;

VOID
HelloWorld (
  VOID
  )
{
  mImports.Print (L"Hello, World!\n");
}

COMMON_EXPORT_API
EFI_STATUS
EFIAPI
LibConstructor (
  IN IMPORTS   *Imports,
  OUT EXPORTS  *Exports
  )
{
  if ((Imports == NULL) || (Imports->Signature != IMPORT_SIGNATURE)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Print function should be safe to call
  //
  if ((Exports == NULL) || (Exports->Signature != EXPORT_SIGNATURE)) {
    Imports->Print (L"Exports is NULL or has an invalid signature\n");
    return EFI_INVALID_PARAMETER;
  }

  mImports.Print = Imports->Print;

  Exports->HelloWorld = HelloWorld;

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
StubEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return EFI_SUCCESS;
}