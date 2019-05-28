/**********************************************************************************************************************
	File Name	:	frame_status.h
	Project		:	Frame
	Author		:	Cory Levy
	Created		:	21/05/2019 @ 23:05
	Description	:	Project global failure statuses.
**********************************************************************************************************************/
#pragma once

/** Enums ************************************************************************************************************/

typedef enum _FRAMESTATUS
{
	FRAMESTATUS_INVALID = -1,
	FRAMESTATUS_SUCCESS = 0,

	FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS,

	FRAMESTATUS_LOADER_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED,

	FRAMESTATUS_LOADER_MAPIMAGEDATA_SECTION_VIRTUALALLOC_FAILED,
	FRAMESTATUS_LOADER_MAPIMAGEDATA_PEHEADERS_VIRTUALALLOC_FAILED,

	FRAMESTATUS_LOADER_LOADEXTERNALSYMBOLS_LOADLIBRARYA_FAILED,
	FRAMESTATUS_LOADER_LOADEXTERNALSYMBOLS_GETPROCADDRESS_FAILED,

	FRAMESTATUS_LOADER_PROTECTMEMORY_VIRTUALFREE_FAILED,
	FRAMESTATUS_LOADER_PROTECTMEMORY_VIRTUALPROTECT_FAILED,

	FRAMESTATUS_LOADER_RESOLVEIMPORTS_LOADLIBRARY_FAILED,
	FRAMESTATUS_LOADER_RESOLVEIMPORTS_GETPROCADDRESS_FAILED,

	// Must be last
	GLOBESTATUS_COUNT
} FRAMESTATUS, *PFRAMESTATUS;

/** Macros ***********************************************************************************************************/

/**********************************************************************************************************************
	Macro		:	FRAME_SUCCESS
	Purpose		:	Check if a given GLOBESTAUTS indicates success.
	Parameters	:	@status - The status to check.
**********************************************************************************************************************/
#define FRAME_SUCCESS(status) (FRAMESTATUS_SUCCESS == status)

/**********************************************************************************************************************
	Macro		:	FRAME_FAILED
	Purpose		:	Check if a given GLOBESTAUTS indicates failure.
	Parameters	:	@status - The status to check.
**********************************************************************************************************************/
#define FRAME_FAILED(status) (!FRAME_SUCCESS(status))




