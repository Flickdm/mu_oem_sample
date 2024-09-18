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

VOID
PrintExportedFunctions (
  IN VOID                        *Image,
  IN EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory
  );

EFI_STATUS
FindExportedFunction (
  IN  VOID                        *Image,
  IN  EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory,
  IN  CHAR8                       *FunctionName,
  OUT UINT32                      *FunctionAddress
  );


EFI_STATUS
GetFunctionAddress (
  IN  VOID   *Image,
  IN  CHAR8  *FunctionName,
  OUT VOID   **FunctionAddress
  );

#endif // SHARED_LOADER_PE_COFF_LIB_H__
