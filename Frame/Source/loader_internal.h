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
	Function	:	loader_ResolveImageImports
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
loader_ResolveImageImports(
	__in_req PVOID pvImage,
	__in PVOID pvImageBase
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
	__in_req HMODULE hDll
);
