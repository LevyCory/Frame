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
	__deref_out PVOID pvDll
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