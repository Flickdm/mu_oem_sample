#include <PiPei.h>
#include <Library/PeiServicesLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/BaseMemoryLib.h>
//#include <Library/PrePiLib.h>

#include "HelloUefiLib/SharedDependencies.h"

EFI_STATUS
DiscoverCryptoBinary (
  IN EFI_GUID   *CryptoBinaryGuid,
  OUT EFI_GUID  *FvGuid,
  OUT VOID      **OutFvBase,
  OUT UINT64     *OutFvSize
  )
{
  EFI_STATUS                 Status;
  EFI_PEI_FV_HANDLE          FvHandle;
  EFI_PEI_FILE_HANDLE        FileHandle;
  EFI_FV_INFO                FvInfo;
  // Search all firmware volumes
  UINTN  Index = 0;

  while (TRUE) {
    Status = PeiServicesFfsFindNextVolume (Index, &FvHandle);
    if (EFI_ERROR (Status)) {
      if (Status == EFI_NOT_FOUND) {
        DEBUG ((DEBUG_INFO, "No more firmware volumes found.\n"));
        break;
      } else {
        DEBUG ((DEBUG_ERROR, "Error finding next volume: %r\n", Status));
        return Status;
      }
    }

    // Get the EFI_GUID of the current firmware volume
    Status = PeiServicesFfsGetVolumeInfo (FvHandle, &FvInfo);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Error getting volume info: %r\n", Status));
      return Status;
    }

    DEBUG ((DEBUG_INFO, "Current firmware volume GUID: %g\n", &FvInfo.FvName));

    // Locate the file by GUID in the current volume
    Status = PeiServicesFfsFindFileByName (CryptoBinaryGuid, FvHandle, &FileHandle);
    if (!EFI_ERROR (Status)) {
      DEBUG ((DEBUG_INFO, "Found file by GUID in volume %u.\n", Index));
      break;
    }

    Index++;
  }

  DEBUG ((DEBUG_INFO, "File found in volume %u.\n", Index));

  *OutFvBase =  FvInfo.FvStart;
  *OutFvSize = FvInfo.FvSize;
  CopyGuid (FvGuid, &FvInfo.FvName);

  return EFI_SUCCESS;
}



/**
Entry to CryptoPeiEntry.

@param FileHandle   The image handle.
@param PeiServices  The PEI services table.

@retval Status      From internal routine or boot object, should not fail
**/
EFI_STATUS
EFIAPI
PeimEntryPoint (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  DEBUG ((DEBUG_INFO, "Doug's Cool PeimEntryPoint\n"));

  EFI_STATUS  Status;

  // Discover the crypto binary

  EFI_PHYSICAL_ADDRESS  CryptoBinaryAddress;
  EFI_GUID              CryptoBinaryGuid = SHARED_FILE_GUID;
  EFI_GUID              FvGuid;
  UINT64                SectionSize;
  VOID*                SectionData;

  Status = DiscoverCryptoBinary (&CryptoBinaryGuid, &FvGuid, &SectionData, &SectionSize);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to discover crypto binary: %r\n", Status));
    return Status;
  }

  CryptoBinaryAddress = (EFI_PHYSICAL_ADDRESS)SectionData;

  DEBUG ((DEBUG_INFO, "Crypto binary found at 0x%lx\n", CryptoBinaryAddress));

  //
  // Create a HOB for the crypto binary
  //
  BuildFv2Hob (CryptoBinaryAddress, SectionSize, &FvGuid, &CryptoBinaryGuid);

  DEBUG ((DEBUG_INFO, "Crypto binary HOB created\n"));

  return EFI_SUCCESS;
}
