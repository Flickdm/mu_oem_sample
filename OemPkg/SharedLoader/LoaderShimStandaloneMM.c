#include "LoaderShim.h"

#include <PiPei.h>

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrePiLib.h>

#include <Guid/FirmwareFileSystem2.h>
#include <Protocol/FirmwareVolume2.h>
#include <Ppi/FirmwareVolumeInfo.h>

#include "HelloUefiLib/SharedDependencies.h"

DRIVER_DEPENDENCIES  *gDriverDependencies = NULL;

// FfsFindFileByName

EFI_STATUS
DiscoverCryptoBinary (
  IN EFI_GUID  *TargetGuid,
  OUT VOID     **OutSectionData,
  OUT UINT64   *OutSectionDataSize
  )
{
  EFI_PEI_HOB_POINTERS        Hob;
  EFI_FIRMWARE_VOLUME_HEADER  *FwVolHeader;
  EFI_FFS_FILE_HEADER         *FileHeader;
  EFI_STATUS                  Status;
  VOID                        *SectionData;
  BOOLEAN                     Found;
  UINTN                       FileSize;

  Found = FALSE;

  Hob.Raw = GetHobList ();
  if (Hob.Raw == NULL) {
    return EFI_NOT_FOUND;
  }

  do {
    Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, Hob.Raw);
    if (Hob.Raw != NULL) {
      FwVolHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)(Hob.FirmwareVolume->BaseAddress);

      FileHeader = NULL;
      Status     = FfsFindNextFile (EFI_FV_FILETYPE_APPLICATION, FwVolHeader, &FileHeader);
      while (!EFI_ERROR (Status)) {
        DEBUG ((DEBUG_INFO, "Found EFI Application: %g\n", &FileHeader->Name));

        if (CompareGuid (&FileHeader->Name, TargetGuid)) {
          DEBUG ((DEBUG_INFO, "Found EFI Application with matching GUID.\n"));
          Found  = TRUE;
          Status = EFI_SUCCESS;
          break;
        }

        Status = FfsFindNextFile (EFI_FV_FILETYPE_APPLICATION, FwVolHeader, &FileHeader);
      }

      Hob.Raw = GetNextHob (EFI_HOB_TYPE_FV, GET_NEXT_HOB (Hob));
    }
  } while (Hob.Raw != NULL);

  if (!Found && !EFI_ERROR (Status)) {
    Status = EFI_NOT_FOUND;
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find file by GUID: %r\n", Status));
    return Status;
  }

  Status = FfsFindSectionData (EFI_SECTION_PE32, FileHeader, &SectionData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to find section with known GUID: %r\n", Status));
    return Status;
  }


  FileSize = 0;
  CopyMem (&FileSize, FileHeader->Size, sizeof (FileHeader->Size));

  *OutSectionDataSize = FileSize - sizeof (EFI_FFS_FILE_HEADER);;
  *OutSectionData = SectionData;

  return EFI_SUCCESS;
}

VOID
InstallDriverDependencies (
  VOID
  )
{
  gDriverDependencies->AllocatePages  = gMmst->MmAllocatePages;
  gDriverDependencies->FreePages      = gMmst->MmFreePages;
  gDriverDependencies->LocateProtocol = gMmst->MmLocateProtocol;
  gDriverDependencies->AllocatePool   = gMmst->MmAllocatePool;
  gDriverDependencies->FreePool       = gMmst->MmFreePool;
}

EFI_STATUS
EFIAPI
MmEntry (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_MM_SYSTEM_TABLE  *MmSystemTable
  )
{
  VOID        *SectionData = NULL;
  UINT64      SectionSize;
  EFI_STATUS  Status;
  EFI_GUID    CommonGuid = SHARED_FILE_GUID;

  if (gDriverDependencies == NULL) {
    gDriverDependencies = AllocatePool (sizeof (*gDriverDependencies));
    if (gDriverDependencies == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    InstallDriverDependencies ();
  }

  Status = DiscoverCryptoBinary (&CommonGuid, &SectionData, &SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to discover crypto binary: %r\n", Status));
    goto Exit;
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

  return Status;
}
