/**********************************************************************************************************************
	File Name	:	loader_internal.h
	Project		:	Frame
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 20:05
	Description	:	Private definitions of the loader module
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include "loader.h"
#include "headers.h"

/** Constants*********************************************************************************************************/

/**********************************************************************************************************************
	Constant	:	MAX_PROC_NAME_SIZE
	Purpose		:	Define the max length of a proc name exported by a dll.
**********************************************************************************************************************/
#define MAX_PROC_NAME_SIZE (256)

/** Typedefs *********************************************************************************************************/

/**********************************************************************************************************************
	Type		:	PFNENTRYPOINT
	Purpose		:	A function pointer type of DllMain.
**********************************************************************************************************************/
typedef BOOL(WINAPI *PFNENTRYPOINT)(HINSTANCE, DWORD, LPVOID);

/** Macros ***********************************************************************************************************/

/**********************************************************************************************************************
	Macro		:	FRAME_RELOCATION_TYPE
	Purpose		:	Return the relocation type.
	Parameters	:	@word - The data to process.
**********************************************************************************************************************/
#define FRAME_RELOCATION_TYPE(word) ((word) >> 12) 

/**********************************************************************************************************************
	Macro		:	FRAME_RELOCATION_OFFSET
	Purpose		:	Return the relocation offset.
	Parameters	:	@word - The data to process.
**********************************************************************************************************************/
#define FRAME_RELOCATION_OFFSET(word) ((word) & 0x0fff) 

/** Functions ********************************************************************************************************/

/**********************************************************************************************************************
	Function	:	loader_AllocateImageMemory
	Purpose		:	Allocates memory for the loaded dll. If the preferred base address is not available, the memory 
					will be allocated in a different address.
	Parameters	:	@pvDll[in] - The dll to load.
					@phDll[out] - The allocated memory.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_AllocateImageMemory(
	__in PVOID pvDll,
	__deref_out HMODULE *phDll
);

/**********************************************************************************************************************
	Function	:	loader_MapImageData
	Purpose		:	Maps the relevant headers of the image.
	Parameters	:	@pvImage[in] - The image whose headers will be mapped.
					@hDll[in\out] - The allocated memory for that image.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_MapImageData(
	__in PVOID pvImage,
	__inout HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_GetSectionPermissions
	Purpose		:	Interprets the IMAGE_SECTION_HEADER.Characteristics into a constant understood by VirtualAlloc.
	Parameters	:	@dwSectionCharacteristics[int] - The section's characteristics.
	Return		:	DWORD
**********************************************************************************************************************/
DWORD
loader_GetSectionPermissions(
	__in DWORD dwSectionCharacteristics
);

/**********************************************************************************************************************
	Function	:	loader_ProtectMemory
	Purpose		:	Sets the memory permissions of each mapped section of the library.
	Parameters	:	@hDll[in\out] - The mapped library to protect it's section.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_ProtectMemory(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_RelocateSymbols
	Purpose		:	Perform needed symbol relocation if a library was not loaded in its preferred address.
	Parameters	:	@hDll[in\out] - The library to relocate.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_RelocateSymbols(
	__in_req HMODULE hDll,
	__in SIZE_T cbRelocationDelta
);

/**********************************************************************************************************************
	Function	:	loader_RelocateSymbols
	Purpose		:	Load necessary external symbols for the library.
	Parameters	:	@hDll[in\out] - The library to load libraries for.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_LoadExternalSymbols(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_FreeExternalLibraries
	Purpose		:	Frees the libraries loaded by the library.
	Parameters	:	@hDll[in] - The loaded library
**********************************************************************************************************************/
VOID
loader_FreeExternalLibraries(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_CallEntryPoint
	Purpose		:	Calls the library's DllMain function.
	Parameters	:	@hDll[in] - The loaded library to notify.
					@dwReason[in] - The reason for calling the entrypoint.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_CallEntryPoint(
	__in_req HMODULE hDll,
	__in DWORD dwReason
);

/**********************************************************************************************************************
	Function	:	loader_GetOrdinalFromName
	Purpose		:	Return the ordinal corresponding to the proc name.
	Parameters	:	@hDll[in] - The library loaded by Frame.
					@pszName[in] - An ASCII string representing the proc name.
					@pwOrdinal[out] - The proc ordinal.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_GetOrdinalFromName(
	__in_req HMODULE hDll,
	__in_req PCSTR pszName,
	__out PWORD pwOrdinal
);

/**********************************************************************************************************************
	Function	:	
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
loader_GetProcByOrdinal(
	__in_req HMODULE hDll,
	__in WORD ordinal,
	__out FARPROC *pfnProc
);