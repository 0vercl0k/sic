// Axel '0vercl0k' Souchet - February 19 2020
#include "sym.h"

#include <memory>

//
// Special thanks to @masthoon for being knowledgeable about dbghelp.
//

bool GetFieldOffset(const DWORD64 Base, const wchar_t *TypeName,
                    const wchar_t *FieldName, DWORD32 *FieldOffset) {
  //
  // Allocate a buffer to back the SYMBOL_INFO structure.
  //

  const DWORD SizeOfStruct =
      sizeof(SYMBOL_INFOW) + ((MAX_SYM_NAME - 1) * sizeof(wchar_t));
  uint8_t SymbolInfoBuffer[SizeOfStruct];
  auto SymbolInfo = PSYMBOL_INFOW(SymbolInfoBuffer);

  //
  // Initialize the fields that need initialization.
  //

  SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
  SymbolInfo->MaxNameLen = MAX_SYM_NAME;

  //
  // Retrieve a type index for the type we're after.
  //

  if (!SymGetTypeFromNameW(GetCurrentProcess(), Base, TypeName, SymbolInfo)) {
    printf("SymGetTypeFromName failed %d.\n", GetLastError());
    return false;
  }

  //
  // Now that we have a type, we need to enumerate its children to find the
  // field we're after. First step is to get the number of children.
  //

  const ULONG TypeIndex = SymbolInfo->TypeIndex;
  DWORD ChildrenCount = 0;
  if (!SymGetTypeInfo(GetCurrentProcess(), Base, TypeIndex,
                      TI_GET_CHILDRENCOUNT, &ChildrenCount)) {
    printf("SymGetTypeInfo failed %d.\n", GetLastError());
    return false;
  }

  //
  // Allocate enough memory to receive the children ids.
  //

  auto FindChildrenParamsBacking = std::make_unique<uint8_t[]>(
      sizeof(_TI_FINDCHILDREN_PARAMS) + ((ChildrenCount - 1) * sizeof(ULONG)));
  auto FindChildrenParams =
      (_TI_FINDCHILDREN_PARAMS *)FindChildrenParamsBacking.get();

  //
  // Initialize the structure with the children count.
  //

  FindChildrenParams->Count = ChildrenCount;

  //
  // Get all the children ids.
  //

  if (!SymGetTypeInfo(GetCurrentProcess(), Base, TypeIndex, TI_FINDCHILDREN,
                      FindChildrenParams)) {
    printf("SymGetTypeInfo2 failed %d.\n", GetLastError());
    return false;
  }

  //
  // Now that we have all the ids, we can walk them and find the one that
  // matches the field we're looking for.
  //

  for (DWORD ChildIdx = 0; ChildIdx < ChildrenCount; ChildIdx++) {
    //
    // Grab the child name.
    //

    const ULONG ChildId = FindChildrenParams->ChildId[ChildIdx];
    WCHAR *ChildName = nullptr;
    SymGetTypeInfo(GetCurrentProcess(), Base, ChildId, TI_GET_SYMNAME,
                   &ChildName);

    //
    // Grab the child size - this is useful to know if a field is a bit or a
    // normal field.
    //

    ULONG64 ChildSize = 0;
    SymGetTypeInfo(GetCurrentProcess(), Base, ChildId, TI_GET_LENGTH,
                   &ChildSize);

    //
    // Does this child's name match the field we're looking for?
    //

    bool Found = false;
    if (wcscmp(ChildName, FieldName) == 0) {
      //
      // If we have found the field, now we need to find its offset if
      // it's a normal field, or its bit position if it is a bit.
      //

      const IMAGEHLP_SYMBOL_TYPE_INFO Info =
          (ChildSize == 1) ? TI_GET_BITPOSITION : TI_GET_OFFSET;
      SymGetTypeInfo(GetCurrentProcess(), Base, ChildId, Info, FieldOffset);
      Found = true;
    }

    //
    // Even if we have found a match, we need to clean up the memory.
    //

    LocalFree(ChildName);
    ChildName = nullptr;

    //
    // We can now break out of the loop if we have what we came looking for.
    //

    if (Found) {
      break;
    }
  }

  //
  // Yay we're done!
  //

  return true;
}

bool GetFieldOffsetFromModule(const wchar_t *ModulePath,
                              const wchar_t *TypeName, const wchar_t *FieldName,
                              DWORD32 *FieldOffset) {
  //
  // Load the symbol table for the module we are interested in.
  //

  const DWORD64 Base = SymLoadModuleExW(GetCurrentProcess(), nullptr,
                                        ModulePath, nullptr, 0, 0, nullptr, 0);
  if (Base == 0) {
    printf("SymLoadModuleEx failed.\n");
    return false;
  }

  //
  // Retrieve the offset of the field.
  //

  const BOOL Success = GetFieldOffset(Base, TypeName, FieldName, FieldOffset);

  //
  // Don't forget to unload the module.
  //

  return Success && SymUnloadModule64(GetCurrentProcess(), Base);
}
