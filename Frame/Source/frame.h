/**
 *  Name        :   frame.h
 *  Author      :   Cory Levy
 *  Date        :   24/05/2019
 */
#pragma once

#include <windows.h>

#include "common.h"
#include "frame_status.h"

/**
 *  Name        :   FRAME_NO_ENTRY_POINT
 *  Purpose     :   Tells Frame to not call the dll's entry point.
 */
#define FRAME_NO_ENTRY_POINT (1)

/**
 *  Constant    :   FRAME_NO_RELOCATION
 *  Purpose     :	Tells frame not to perform symbol relocation. If the library's preferred address is unavailable
 *                  FRAME_LoadLibrary will fail.
 */
#define FRAME_NO_RELOCATION (2)

/**
 *  Function    :   Loads a library from memory.
 *  Parameters  :   @pvDll[in] - The buffered dll.
 *                  @dwFlags[in] - Flags that can change the loader behaviour.
 *                  @phDll[out] - The loaded library.
 *  Return      :   FRAMESTATUS
 */
FRAMESTATUS
FRAME_LoadLibrary(
    __in PVOID pvDll,
    __in DWORD dwFlags,
    __deref_out HMODULE *phDlll
);

/**
 *  Function    :   FRAME_FreeLibrary
 *  Parameters  :   @hDll[in] - A library loaded with FRAME_LoadLibrary.
 */
VOID
FRAME_FreeLibrary(
    HMODULE hDll
);

/**
 *  Function    :   FRAME_GetProcAddress
 *  Purpose     :   Load symbols exported by the dll library loaded by Frame.
 *  Parameters  :   @hDll[in] - The loaded library handle.
 *                  @pszProcName[in] - An ascii string representing the name of the function or its ordinal.
 *                  @pfnProc[out] - The loaded symbol.
 *  Return      :   FRAMESTATUS
 */
FRAMESTATUS
FRAME_GetProcAddress(
    __in_req HMODULE hDll,
    __in_req LPCSTR pszProcName,
    __out FARPROC *pfnProc
);

