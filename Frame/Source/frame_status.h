/**********************************************************************************************************************
	File Name	:	frame_status.h
	Project		:	Frame
	Author		:	Cory Levy
	Created		:	21/05/2019 @ 23:05
	Description	:	
**********************************************************************************************************************/
#pragma once

/** Enums ************************************************************************************************************/

typedef enum _FRAMESTATUS
{
	FRAMESTATUS_INVALID = -1,
	FRAMESTATUS_SUCCESS = 0,

	FRAMESTATUS_LOADER_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED,

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



