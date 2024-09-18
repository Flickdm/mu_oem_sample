#include <Uefi.h>

#define COMMON_GUID { 0x1C50FE8C, 0x8607, 0x4CB0, { 0x90, 0x50, 0x48, 0xF6, 0xEE, 0x46, 0xBB, 0x82 } }

#define IMPORT_SIGNATURE  SIGNATURE_32('I','M','P','!')
#define EXPORT_SIGNATURE  SIGNATURE_32('E','X','P','!')

#define IMPORT_VERSION  {0x0, 0x1, 0x0, 0x0}
#define EXPORT_VERSION  {0x0, 0x1, 0x0, 0x0}

typedef VOID (EFIAPI *PRINT_FUNCTION)(IN UINTN ErrorLevel, IN CHAR8 *Format, ...);

#define VERSION

#define CONSTRUCTOR_NAME  "LibConstructor"

typedef struct _IMPORTS {
  UINT32            Signature;
  PRINT_FUNCTION    Print;
} IMPORTS;

typedef VOID (EFIAPI *HELLOWORLD)();

typedef struct _EXPORTS {
  UINT32        Signature;
  HELLOWORLD    HelloWorld;
} EXPORTS;

#if defined(_MSC_VER)
  #define COMMON_EXPORT_API                          __declspec(dllexport)
#else
  #define COMMON_EXPORT_API
#endif

typedef EFI_STATUS (EFIAPI *LIB_CONSTRUCTOR)(IMPORTS *Imports);

COMMON_EXPORT_API
EFI_STATUS
EFIAPI
LibConstructor (
    IMPORTS *Imports
  );