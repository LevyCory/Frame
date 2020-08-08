/**********************************************************************************************************************
    File Name   :   headers.h
    Project     :   Frame
    Author      :   Cory Levy
    Created     :   18/05/2019 @ 21:05
    Description :   Provides macros for easy parsing of in-memory PE files.
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include <winnt.h>
#include "common.h"

/** Macros ***********************************************************************************************************/
/**********************************************************************************************************************
    Macro       :   FRAME_DOS_HEADER
    Purpose     :   Converts a memory address to the DOS header pointer.
    Parameters  :   @ parameter - Description
**********************************************************************************************************************/
#define FRAME_DOS_HEADER(pvMemory) ((PIMAGE_DOS_HEADER)pvMemory)

/**********************************************************************************************************************
    Macro       :   FRAME_PE_HEADER
    Purpose     :   Return a pointer to the NT headers of the PE file.
    Parameters  :   @pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_NT_HEADER(pvMemory) ((PIMAGE_NT_HEADERS)ADD_POINTERS(pvMemory, FRAME_DOS_HEADER(pvMemory)->e_lfanew))

/**********************************************************************************************************************
    Macro       :   FRAME_FILE_HEADER
    Purpose     :   Return a pointer to the file header of the PE file.
    Parameters  :   @pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_FILE_HEADER(pvMemory) ((PIMAGE_FILE_HEADER)(&FRAME_NT_HEADER(pvMemory)->FileHeader))

/**********************************************************************************************************************
    Macro       :   FRAME_OPTIONAL_HEADER
    Purpose     :   Return a pointer to the optional header of the PE file.
    Parameters  :   @pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_OPTIONAL_HEADER(pvMemory) ((PIMAGE_OPTIONAL_HEADER)(&FRAME_NT_HEADER(pvMemory)->OptionalHeader))

/**********************************************************************************************************************
    Macro       :   FRAME_SECTION_HEADER
    Purpose     :   Return a pointer to the first section header of the PE file.
    Parameters  :   @pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_SECTION_HEADER(pvMemory) ((PIMAGE_SECTION_HEADER)ADD_POINTERS(FRAME_OPTIONAL_HEADER(pvMemory), sizeof(IMAGE_OPTIONAL_HEADER)))

/**********************************************************************************************************************
    Macro       :   FRAME_DATA_DIRECTORY_ENTRY
    Purpose     :   Return a pointer to a data directory entry of the PE file.
    Parameters  :   @hDll[in] - The in-memory PE file
                    @dwIndex[in] - The index of the needed directory.
**********************************************************************************************************************/
#define FRAME_DATA_DIRECTORY_ENTRY(hDll, dwIndex) ((PIMAGE_DATA_DIRECTORY)&(FRAME_OPTIONAL_HEADER(hDll)->DataDirectory[dwIndex]))

/**********************************************************************************************************************
    Macro       :   FRAME_DATA_DIRECTORY
    Purpose     :
    Parameters  :   @ parameter - Description
**********************************************************************************************************************/
#define FRAME_DATA_DIRECTORY(hDll, dwIndex) ADD_POINTERS(hDll, FRAME_DATA_DIRECTORY_ENTRY(hDll, dwIndex)->VirtualAddress); 
