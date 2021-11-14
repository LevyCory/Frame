﻿/** 
 *  Name        :   frame_status.h
 *  Author      :   Cory Levy
 *  Created     :   21/05/2019
 *  Description :   Project global failure statuses.
 */
#pragma once

typedef enum _FRAMESTATUS
{
    FRAMESTATUS_INVALID = -1,
    FRAMESTATUS_SUCCESS = 0,

    FRAMESTATUS_FRAME_LOADLIBRARY_INVALID_PARAMETERS,

    FRAMESTATUS_FRAME_GETPROCADDRESS_INVALID_PARAMETERS,
    FRAMESTATUS_FRAME_GETPROCADDRESS_PROC_NOT_FOUND,

    FRAMESTATUS_FRAME_CALLENTRYPOINT_ENTRYPOINT_FAILED,

    FRAMESTATUS_FRAME_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED,

    FRAMESTATUS_FRAME_MAPIMAGEDATA_SECTION_VIRTUALALLOC_FAILED,
    FRAMESTATUS_FRAME_MAPIMAGEDATA_PEHEADERS_VIRTUALALLOC_FAILED,

    FRAMESTATUS_FRAME_LOADEXTERNALSYMBOLS_LOADLIBRARYA_FAILED,
    FRAMESTATUS_FRAME_LOADEXTERNALSYMBOLS_GETPROCADDRESS_FAILED,

    FRAMESTATUS_FRAME_PROTECTMEMORY_VIRTUALFREE_FAILED,
    FRAMESTATUS_FRAME_PROTECTMEMORY_VIRTUALPROTECT_FAILED,

    FRAMESTATUS_FRAME_RELOCATESYMBOLS_INVALID_RELOCATION_TYPE,

    FRAMESTATUS_FRAME_RESOLVEIMPORTS_LOADLIBRARY_FAILED,
    FRAMESTATUS_FRAME_RESOLVEIMPORTS_GETPROCADDRESS_FAILED,

    FRAMESTATUS_LOADERGETORDINALFROMNAME_NAME_NOT_FOUND,

    // Must be last
    FRAMESTATUS_COUNT
} FRAMESTATUS, *PFRAMESTATUS;

#define FRAME_SUCCESS(status) (FRAMESTATUS_SUCCESS == status)
#define FRAME_FAILED(status) (!FRAME_SUCCESS(status))




