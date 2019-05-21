/**********************************************************************************************************************
	File Name	:	loader.c
	Project		:	Globe
	Author		:	Cory Levy
	Created		:	18/05/2019 @ 20:05
	Description	:
**********************************************************************************************************************/
/** Headers **********************************************************************************************************/

#include "loader_internal.h"

/** Functions ********************************************************************************************************/

/**********************************************************************************************************************
	Function	: loader_AllocateImageMemory
**********************************************************************************************************************/
FRAMESTATUS
loader_AllocateImageMemory(
	__in PVOID pvDll,
	__out HMODULE *phDll
)
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
	PIMAGE_OPTIONAL_HEADER ptHeader = FRAME_OPTIONAL_HEADER(pvDll);
	PVOID hDll = NULL;

	ASSERT(NULL != pvDll);
	ASSERT(NULL != phDll);

	hDll = VirtualAlloc(ptHeader->ImageBase, ptHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (NULL == hDll)
	{
		hDll = VirtualAlloc(NULL, 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (NULL == hDll)
		{
			eStatus = FRAMESTATUS_LOADER_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED;
			goto lblCleanup;
		}
	}

	*phDll = (HMODULE)hDll;
	hDll = NULL;

lblCleanup:
	if (NULL != hDll)
	{
		(VOID)VirtualFree(hDll, 0, MEM_RELEASE);
	}

	return eStatus;
}

/**********************************************************************************************************************
	Function	:	loader_LoadImageData
**********************************************************************************************************************/
FRAMESTATUS
loader_MapImageData(
	__in PVOID pvImage,
	__inout HMODULE hDll
)
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;

lblCleanup:
	return eStatus;
}