#ifndef SHARED_LOADER_PE_COFF_LIB_H__
#define SHARED_LOADER_PE_COFF_LIB_H__

#include <Uefi.h>
#include <Library/PeCoffLib.h>

/**
  Get the Export Directory in a PE/COFF image.

  This function retrieves the Export Directory in a PE/COFF image.

  @param[in]  Image                     A pointer to the base address of the PE/COFF image.
  @param[in]  PeCoffLoaderImageContext   A pointer to the PE_COFF_LOADER_IMAGE_CONTEXT structure.
  @param[out] ImageExportDirectory      A pointer to the Export Directory structure.

  @retval EFI_SUCCESS                    The Export Directory is found.
  @retval EFI_INVALID_PARAMETER          A parameter is invalid.
  @retval EFI_UNSUPPORTED                The image is not a valid PE/COFF image.
  @retval EFI_NOT_FOUND                  The Export Directory is not found.
**/
EFI_STATUS
GetExportDirectoryInPeCoffImage (
  IN  VOID                          *Image,
  IN  PE_COFF_LOADER_IMAGE_CONTEXT  *PeCoffLoaderImageContext,
  OUT EFI_IMAGE_EXPORT_DIRECTORY    **ImageExportDirectory
  );

/**
  Print the exported functions in a PE/COFF image.

  This function prints the exported functions in a PE/COFF image.

  @param[in] Image              A pointer to the base address of the PE/COFF image.
  @param[in] ExportDirectory    A pointer to the Export Directory structure.
**/
VOID
PrintExportedFunctions (
  IN VOID                        *Image,
  IN EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory
  );

/**
  Find an exported function in a PE/COFF image.

  This function finds an exported function in a PE/COFF image.

  @param[in]  Image            A pointer to the base address of the PE/COFF image.
  @param[in]  ExportDirectory  A pointer to the Export Directory structure.
  @param[in]  FunctionName     A pointer to the function name.
  @param[out] FunctionAddress  A pointer to the function address.

  @retval EFI_SUCCESS           The function is found.
  @retval EFI_INVALID_PARAMETER A parameter is invalid.
  @retval EFI_NOT_FOUND         The function is not found.
**/
EFI_STATUS
FindExportedFunction (
  IN  VOID                        *Image,
  IN  EFI_IMAGE_EXPORT_DIRECTORY  *ExportDirectory,
  IN  CHAR8                       *FunctionName,
  OUT UINT32                      *FunctionAddress
  );

#endif // SHARED_LOADER_PE_COFF_LIB_H__
