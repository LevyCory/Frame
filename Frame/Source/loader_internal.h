/**********************************************************************************************************************
	File Name	:	loader_internal.h
	Project		:	Globe
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 20:05
	Description	:
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include "loader.h"
#include "headers.h"

/** Typedefs *********************************************************************************************************/

typedef BOOL(WINAPI *PFNENTRYPOINT)(HINSTANCE, DWORD, LPVOID);

/** Macros ***********************************************************************************************************/

/**********************************************************************************************************************
	Macro		:	FRAME_RELOCATION_TYPE
	Purpose		:	
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_RELOCATION_TYPE(word) ((word) >> 12) 

/**********************************************************************************************************************
	Macro		:	FRAME_RELOCATION_OFFSET
	Purpose		:	
	Parameters	:	@ parameter - Description
**********************************************************************************************************************/
#define FRAME_RELOCATION_OFFSET(word) ((word) & 0x0fff) 

/** Functions ********************************************************************************************************/
/**********************************************************************************************************************
	Function	:	loader_AllocateImageMemory
	Parameters	:	@pvDll[in] -
					@phDll[out] -
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
loader_AllocateImageMemory(
	__in PVOID pvDll,
	__deref_out HMODULE *phDll
);

/**********************************************************************************************************************
	Function	:	loader_MapImageData
	Parameters	:	@pvImage[in\out\opt] -
					@hDll[in\out\opt] -
	Return		:	FRAMESTATUS
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
loader_MapImageData(
	__in PVOID pvImage,
	__inout HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_GetSectionPermissions
	Parameters	:	@pvImage[in\out\opt] -
					@hDll[in\out\opt] -
	Return		:	FRAMESTATUS
	Remarks		:
**********************************************************************************************************************/
DWORD
loader_GetSectionPermissions(
	__in DWORD dwSectionCharacteristics
);

/**********************************************************************************************************************
	Function	:	loader_ProtectMemory
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
loader_ProtectMemory(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_RelocateSymbols
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
loader_RelocateSymbols(
	__in_req HMODULE hDll,
	__in SIZE_T cbRelocationDelta
);

/**********************************************************************************************************************
	Function	:	loader_RelocateSymbols
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
loader_LoadExternalSymbols(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
VOID
loader_FreeExternalLibraries(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	loader_CallEntryPoint
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
VOID
loader_CallEntryPoint(
	__in_req HMODULE hDll,
	__in DWORD dwReason
);
