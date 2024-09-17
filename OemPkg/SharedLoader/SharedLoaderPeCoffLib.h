#ifndef SHARED_LOADER_PE_COFF_LIB_H__
#define SHARED_LOADER_PE_COFF_LIB_H__

#include <Uefi.h>
#include <Library/PeCoffLib.h>

EFI_STATUS
GetExportDirectoryInPeCoffImage (
  IN  VOID                          *Image,
  IN  PE_COFF_LOADER_IMAGE_CONTEXT  *PeCoffLoaderImageContext,
  OUT EFI_IMAGE_EXPORT_DIRECTORY    **ImageExportDirectory
  );

#endif // SHARED_LOADER_PE_COFF_LIB_H__