/**
 *  Name        :   common.h
 *  Author      :   Cory Levy
 *  Created     :   10/03/2019 @ 21:03
 *  Description :   Common macros and constants.
 */
#pragma once

#include <windows.h>

/**
 *  Name        :   ASSERT
 *  Purpose     :   Invokes breakpoint if the condition is false.
 *  Parameters  :   @expression - The expression to evaluate.
 */
#ifdef _DEBUG
#define ASSERT(expression) if(!(expression)) { __debugbreak(); }
#else
#define ASSERT(expression) 
#endif

/**
 *  Name        :   __in_req
 *  Purpose     :   SAL annotation to denote both __in and __notnull.
 */
#define __in_req __in __notnull

/**
 *  Macro       :   PTR_ADD
 *  Purpose     :   Add two pointers together
 */
#define PTR_ADD(first, second) (PVOID)((SIZE_T)(first) + (SIZE_T)(second))

/**
 *  Macro       :   PTR_SUB
 *  Purpose     :   Sub one pointer from another
 */
#define PTR_SUB(first, second) (PVOID)((SIZE_T)(first) - (SIZE_T)(second))

/**
 *  Macro       :   FRAME_DOS_HEADER
 *  Purpose     :   Converts a memory address to the DOS header pointer.
 *  Parameters  :   @ parameter - Description
 */
#define FRAME_DOS_HEADER(pvMemory) ((PIMAGE_DOS_HEADER)pvMemory)

/**
 *  Macro       :   FRAME_PE_HEADER
 *  Purpose     :   Return a pointer to the NT headers of the PE file.
 *  Parameters  :   @pvMemory[in] - The in-memory PE file
 */
#define FRAME_NT_HEADER(pvMemory) ((PIMAGE_NT_HEADERS)PTR_ADD(pvMemory, FRAME_DOS_HEADER(pvMemory)->e_lfanew))

/**
 *  Macro       :   FRAME_FILE_HEADER
 *  Purpose     :   Return a pointer to the file header of the PE file.
 *  Parameters  :   @pvMemory[in] - The in-memory PE file
 */
#define FRAME_FILE_HEADER(pvMemory) ((PIMAGE_FILE_HEADER)(&FRAME_NT_HEADER(pvMemory)->FileHeader))

/**
 *  Macro       :   FRAME_OPTIONAL_HEADER
 *  Purpose     :   Return a pointer to the optional header of the PE file.
 *  Parameters  :   @pvMemory[in] - The in-memory PE file
 */
#define FRAME_OPTIONAL_HEADER(pvMemory) ((PIMAGE_OPTIONAL_HEADER)(&FRAME_NT_HEADER(pvMemory)->OptionalHeader))

/**
 *  Macro       :   FRAME_SECTION_HEADER
 *  Purpose     :   Return a pointer to the first section header of the PE file.
 *  Parameters  :   @pvMemory[in] - The in-memory PE file
 */
#define FRAME_SECTION_HEADER(pvMemory) ((PIMAGE_SECTION_HEADER)PTR_ADD(FRAME_OPTIONAL_HEADER(pvMemory), sizeof(IMAGE_OPTIONAL_HEADER)))

/**
 *  Macro       :   FRAME_DATA_DIRECTORY_ENTRY
 *  Purpose     :   Return a pointer to a data directory entry of the PE file.
 *  Parameters  :   @hDll[in] - The in-memory PE file
 *                  @dwIndex[in] - The index of the needed directory.
 */
#define FRAME_DATA_DIRECTORY_ENTRY(hDll, dwIndex) ((PIMAGE_DATA_DIRECTORY)&(FRAME_OPTIONAL_HEADER(hDll)->DataDirectory[dwIndex]))

/**
 *  Macro       :   FRAME_DATA_DIRECTORY
 *  Purpose     :
 *  Parameters  :   @ parameter - Description
 */
#define FRAME_DATA_DIRECTORY(hDll, dwIndex) PTR_ADD(hDll, FRAME_DATA_DIRECTORY_ENTRY(hDll, dwIndex)->VirtualAddress); 

