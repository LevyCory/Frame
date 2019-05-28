/**********************************************************************************************************************
	File Name	:	headers.h
	Project		:	Frame
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 21:05
	Description	:	Provides macros for easy parsing of in-memory PE files.
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include <winnt.h>

/** Macros ***********************************************************************************************************/
/**********************************************************************************************************************
	Macro		:	FRAME_PE_HEADER
	Purpose		:	Return a pointer to the NT headers of the PE file.
	Parameters	:	@pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_NT_HEADER(pvMemory) ((PIMAGE_NT_HEADERS)(pvMemory))

/**********************************************************************************************************************
	Macro		:	FRAME_FILE_HEADER
	Purpose		:	Return a pointer to the file header of the PE file.
	Parameters	:	@pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_FILE_HEADER(pvMemory) ((PIMAGE_FILE_HEADER)(&FRAME_NT_HEADER(pvMemory)->FileHeader))

/**********************************************************************************************************************
	Macro		:	FRAME_OPTIONAL_HEADER
	Purpose		:	Return a pointer to the optional header of the PE file.
	Parameters	:	@pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_OPTIONAL_HEADER(pvMemory) ((PIMAGE_OPTIONAL_HEADER)(&FRAME_NT_HEADER(pvMemory)->OptionalHeader))

/**********************************************************************************************************************
	Macro		:	FRAME_SECTION_HEADER
	Purpose		:	Return a pointer to the first section header of the PE file.
	Parameters	:	@pvMemory[in] - The in-memory PE file
**********************************************************************************************************************/
#define FRAME_SECTION_HEADER(pvMemory) ((PIMAGE_SECTION_HEADER)ADD_POINTERS(pvMemory, 0x138))

/**********************************************************************************************************************
	Macro		:	FRAME_DATA_DIRECTORY
	Purpose		:	Return a pointer to a data directory entry of the PE file.
	Parameters	:	@hDll[in] - The in-memory PE file
					@dwIndex[in] - The index of the needed directory.
**********************************************************************************************************************/
#define FRAME_DATA_DIRECTORY(hDll, dwIndex) ((PIMAGE_DATA_DIRECTORY)&(FRAME_OPTIONAL_HEADER(hDll)->DataDirectory[dwIndex]))

