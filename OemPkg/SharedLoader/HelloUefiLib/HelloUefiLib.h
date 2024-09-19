#ifndef HELLO_UEFI_LIB_
#define HELLO_UEFI_LIB_

#include <Uefi.h>
#include "SharedDependencies.h"

#if defined (_MSC_VER)
#define COMMON_EXPORT_API  __declspec(dllexport)
#else
#define COMMON_EXPORT_API
#endif

#define DEBUG_INFO      0x00000040       // Informational debug messages


COMMON_EXPORT_API
EFI_STATUS
EFIAPI
Constructor (
  DEPENDENCIES  *Depends
  );

#endif