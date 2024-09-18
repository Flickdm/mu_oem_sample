#include <uefi.h>

#include "Common.h"

IMPORTS  mImports;

VOID
HelloWorld (
  VOID
  )
{
  mImports.Print (0x00000040, "Hello, World!\n");
}

COMMON_EXPORT_API
EFI_STATUS
EFIAPI
LibConstructor (
  IMPORTS *Imports
  )
{
  if (Imports == NULL || Imports->Signature != IMPORT_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  if (Imports->Print == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mImports.Print = Imports->Print;

  mImports.Print (0x00000040, "LibConstructor calling back!\n");


  //
  // Print function should be safe to call
  //
  //if ((Exports == NULL) || (Exports->Signature != EXPORT_SIGNATURE)) {
  //  Imports->Print (0x00000040, "Exports is NULL or has an invalid signature\n");
  //  return EFI_INVALID_PARAMETER;
  //}

  // mImports.Print = Imports->Print;

  // Exports->HelloWorld = HelloWorld;

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