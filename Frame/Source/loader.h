/**********************************************************************************************************************
	File Name	:	loader.h
	Project		:	Globe
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 20:05
	Description	:
**********************************************************************************************************************/
#pragma once

/** Headers **********************************************************************************************************/

#include <windows.h>
#include <winnt.h>

#include "common.h"
#include "frame_status.h"

/** Functions ********************************************************************************************************/

FRAMESTATUS
LOADER_LoadLibrary(
	__in PVOID pvAddress,
	__deref_out PVOID pvDll
);


FRAMESTATUS
LOADER_FreeLibrary(
	__in_req HMODULE hDll
);