/**********************************************************************************************************************
	File Name	:	loader.h
	Project		:	Frame
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 20:05
	Description	:	Header file of the loader. Provides dll loading tools.
*********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include <windows.h>
#include <winnt.h>

#include "common.h"
#include "frame_status.h"

/** Constants*********************************************************************************************************/

/**********************************************************************************************************************
	Constant	:	FRAME_NO_ENTRY_POINT
	Purpose		:	Tells Frame to not call the dll's entry point.	
**********************************************************************************************************************/
#define FRAME_NO_ENTRY_POINT (1)

/** Functions ********************************************************************************************************/

/**********************************************************************************************************************
	Function	:	LOADER_LoadLibrary
	Purpose		:	Loads a library from a buffer.
	Parameters	:	@pvImage[in] - The library to load as a memory buffer.
					@pvDll[out] - The loaded library.
	Return		:	FRAMESTATUS
**********************************************************************************************************************/
FRAMESTATUS
LOADER_LoadLibrary(
	__in PVOID pvImage,
	__in DWORD dwFlags,
	__deref_out HMODULE *phDll
);

/**********************************************************************************************************************
	Function	:	LOADER_FreeLibrary
	Purpose		:	Frees a library loaded by frame.
	Parameters	:	@hDll[in] -The library to free.
**********************************************************************************************************************/
VOID
LOADER_FreeLibrary(
	__in_req HMODULE hDll
);

/**********************************************************************************************************************
	Function	:	LOADER_GetProcAddress
	Parameters	:	@param[in\out\opt] -
					@param[in\out\opt] -
	Return		:
	Remarks		:
**********************************************************************************************************************/
FRAMESTATUS
LOADER_GetProcAddress(
	__in_req HMODULE hDll,
	__in_req PSTR pszProcName,
	__out FARPROC *pfnProc
);
