/**********************************************************************************************************************
	File Name	:	headers.h
	Project		:	Globe
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 21:05
	Description	:
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include <winnt.h>

/** Macros ***********************************************************************************************************/
/**********************************************************************************************************************
	Macro		:	FRAME_PE_HEADER
	Purpose		:
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_NT_HEADER(memory) ((PIMAGE_NT_HEADERS)(memory))

/**********************************************************************************************************************
	Macro		:	FRAME_FILE_HEADER
	Purpose		:
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_FILE_HEADER(memory) (PIMAGE_FILE_HEADER)(&(FRAME_NT_HEADER(memory)->FileHeader))

/**********************************************************************************************************************
	Macro		:	FRAME_OPTIONAL_HEADER
	Purpose		:
		Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_OPTIONAL_HEADER(memory) (PIMAGE_OPTIONAL_HEADER)(&(FRAME_NT_HEADER(memory)->OptionalHeader))

/**********************************************************************************************************************
	Macro		:	FRAME_SECTION_HEADER
	Purpose		:
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_SECTION_HEADER(memory) ((PIMAGE_SECTION_HEADER)ADD_POINTERS(memory, 0x138))

/**********************************************************************************************************************
	Macro		:	FRAME_IMPORT_DIRECTORY_RVA
	Purpose		:	
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_IMPORT_DIRECTORY_RVA(memory) (FRAME_OPTIONAL_HEADER(memory)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)

/**********************************************************************************************************************
	Macro		:	FRAME_IMPORT_LIST
	Purpose		:	
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_IMPORT_LIST(ImageBase, Memory) (PIMAGE_IMPORT_DESCRIPTOR)ADD_POINTERS(ImageBase, FRAME_IMPORT_DIRECTORY_RVA(Memory))

