/**********************************************************************************************************************
	File Name	:	loader_internal.h
	Project		:	Frame
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 20:05
	Description	:	Private definitions of Frame.
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include "frame.h"
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

/**********************************************************************************************************************
	Macro		:	GET_INT_RESOURCE
	Purpose		:	Extracts the lower word of the parameter. 	
**********************************************************************************************************************/
#define GET_INT_RESOURCE(resource) ((0x0000ffff) & (SIZE_T)(resource))

/** Functions ********************************************************************************************************/

/**********************************************************************************************************************
	Function	:	frame_AllocateImageMemory
	Purpose		:	Allocates memory for the loaded dll. If the preferred base address is not available, the memory 
					will be allocated in a different address.
	Parameters	:	@pvDll[in] - The dll to load.
					@phDll[out] - The allocated memory.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_AllocateImageMemory(
	__in PVOID pvDll,
	__in BOOL bNoRelocation,
	__deref_out HMODULE *phDll
);

/**********************************************************************************************************************
	Function	:	frame_MapImageData
	Purpose		:	Maps the relevant headers of the image.
	Parameters	:	@pvImage[in] - The image whose headers will be mapped.
					@hDll[in\out] - The allocated memory for that image.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_MapImageData(
	__in PVOID pvImage,
	__inout HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	frame_GetSectionPermissions
	Purpose		:	Interprets the IMAGE_SECTION_HEADER.Characteristics into a constant understood by VirtualAlloc.
	Parameters	:	@dwSectionCharacteristics[int] - The section's characteristics.
	Return		:	DWORD
**********************************************************************************************************************/
DWORD
frame_GetSectionPermissions(
	__in DWORD dwSectionCharacteristics
);

/**********************************************************************************************************************
	Function	:	frame_ProtectMemory
	Purpose		:	Sets the memory permissions of each mapped section of the library.
	Parameters	:	@hDll[in\out] - The mapped library to protect it's section.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_ProtectMemory(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	frame_RelocateSymbols
	Purpose		:	Perform needed symbol relocation if a library was not loaded in its preferred address.
	Parameters	:	@hDll[in\out] - The library to relocate.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_RelocateSymbols(
	__in_req HMODULE hDll,
	__in SIZE_T cbRelocationDelta
);

/**********************************************************************************************************************
	Function	:	frame_RelocateSymbols
	Purpose		:	Load necessary external symbols for the library.
	Parameters	:	@hDll[in\out] - The library to load libraries for.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_LoadExternalSymbols(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	frame_FreeExternalLibraries
	Purpose		:	Frees the libraries loaded by the library.
	Parameters	:	@hDll[in] - The loaded library
**********************************************************************************************************************/
VOID
frame_FreeExternalLibraries(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	frame_CallEntryPoint
	Purpose		:	Calls the library's DllMain function.
	Parameters	:	@hDll[in] - The loaded library to notify.
					@dwReason[in] - The reason for calling the entrypoint.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_CallEntryPoint(
	__in_req HMODULE hDll,
	__in DWORD dwReason
);

/**********************************************************************************************************************
	Function	:	frame_GetOrdinalFromName
	Purpose		:	Return the ordinal corresponding to the proc name.
	Parameters	:	@hDll[in] - The library loaded by Frame.
					@pszName[in] - An ASCII string representing the proc name.
					@pwOrdinal[out] - The proc ordinal.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
frame_GetOrdinalFromName(
	__in_req HMODULE hDll,
	__in_req PCSTR pszName,
	__out PWORD pwOrdinal
);

/**********************************************************************************************************************
	Function	:	Loads a function by its index on the export table.
	Parameters	:	@hDll[in] - The loaded dll.
					@wOrdinal[in] - The function's index in the export table.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FARPROC
frame_GetProcByOrdinal(
	__in_req HMODULE hDll,
	__in WORD wOrdinal
);
