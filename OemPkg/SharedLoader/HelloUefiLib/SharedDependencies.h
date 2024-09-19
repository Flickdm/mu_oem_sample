
#ifndef SHARED_DEPENDENCIES_H
#define SHARED_DEPENDENCIES_H
#include "Uefi.h"

//
// The signature of
//
#define DEPENDS_SIGNATURE  SIGNATURE_32('D','E','P','S')

//
// Version information
//
#define MAJOR 0
#define MINOR 0
#define REVISION 1

#define DEPENDS_VERSION  ((MAJOR << 16) | (MINOR << 8) | REVISION)

//
// FILE_GUID of the *.inf
//
#define SHARED_FILE_GUID  { 0x1C50FE8C, 0x8607, 0x4CB0, { 0x90, 0x50, 0x48, 0xF6, 0xEE, 0x46, 0xBB, 0x82 } }

//
// The name of the exported function
//
#define CONSTRUCTOR_NAME  "Constructor"

///

/**
  @typedef DEBUG_PRINT_FUNCTION
  @brief Defines a function pointer type for a debug print function.

  @param ErrorLevel The error level of the debug message.
  @param Format The format string for the debug message.
  @param ... Additional arguments for the format string.
**/
typedef VOID (EFIAPI *DEBUG_PRINT_FUNCTION)(IN UINTN ErrorLevel, IN CHAR8 *Format, ...);


//
// These represent the dependencies that the phase independent
//
typedef struct _DEPENDENCIES {
    UINT32                  Signature;
    UINT32                  Version;
    DEBUG_PRINT_FUNCTION    DebugPrint;
} DEPENDENCIES;

/**
 * @typedef CONSTRUCTOR
 * @brief Defines a function pointer type for a constructor function.
 *
 * @param Imports A pointer to an IMPORTS structure.
 *
 * @return EFI_STATUS The status of the constructor function.
 */

typedef EFI_STATUS (EFIAPI *CONSTRUCTOR)(DEPENDENCIES *Depends);




#endif