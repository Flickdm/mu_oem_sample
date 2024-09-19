#include <uefi.h>

#include "HelloUefiLib.h"

DEPENDENCIES  mDepends;

EFI_STATUS
VerifyDependsVersion (
  DEPENDENCIES  *Depends,
  UINT32        ExpectedVersion
  )
{
  if (Depends == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Depends->Version != ExpectedVersion) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
SetupDependencies (
  DEPENDENCIES  *Depends
  )
{
  EFI_STATUS  Status;

  if (Depends == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Depends->Signature != DEPENDS_SIGNATURE) {
    return EFI_INVALID_PARAMETER;
  }

  Status = VerifyDependsVersion (Depends, DEPENDS_VERSION);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Depends->DebugPrint == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mDepends.DebugPrint = Depends->DebugPrint;

  return EFI_SUCCESS;
}

COMMON_EXPORT_API
EFI_STATUS
EFIAPI
Constructor (
  DEPENDENCIES  *Depends
  )
{
  EFI_STATUS  Status;

  Status = SetupDependencies (Depends);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mDepends.DebugPrint (DEBUG_INFO, "Dependencies have been succesfully setup!\n");

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
StubEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  SystemTable->ConOut->OutputString (SystemTable->ConOut, L"This DLL cannot be run as a UEFI Application");

  return EFI_SUCCESS;
}
