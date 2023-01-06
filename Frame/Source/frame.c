/**
 *  Name        :   frame.c
 *  Author      :   Cory Levy
 *  Created     :   29/05/2019
 */
#include "frame.h"
#include "frame_internal.h"

DWORD
frame_GetSectionPermissions(
    __in DWORD dwSectionCharacteristics
)
{
    DWORD dwPermissions = 0;
    DWORD dwSimpleCharacteristics =
        (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE) & dwSectionCharacteristics;

    switch (dwSimpleCharacteristics)
    {
    case IMAGE_SCN_MEM_READ:
        return PAGE_READONLY;
    case IMAGE_SCN_MEM_WRITE:
        return PAGE_WRITECOPY;
    case IMAGE_SCN_MEM_EXECUTE:
        return PAGE_EXECUTE;
    case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE):
        return PAGE_READWRITE;
    case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE):
        return PAGE_EXECUTE_READ;
    case (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE):
        return PAGE_EXECUTE_WRITECOPY;
    case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE):
        return PAGE_EXECUTE_READWRITE;
    default:
        return PAGE_NOACCESS;
    }
}

FRAMESTATUS
frame_AllocateImageMemory(
    __in PVOID pvDll,
    __in BOOL bNoRelocation,
    __out HMODULE *phDll
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PIMAGE_OPTIONAL_HEADER ptHeader = FRAME_OPTIONAL_HEADER(pvDll);
    PVOID hDll = NULL;

    ASSERT(pvDll);
    ASSERT(phDll);

    hDll = VirtualAlloc((PVOID)ptHeader->ImageBase, ptHeader->SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
    if (!hDll)
    {
        if (bNoRelocation)
        {
            eStatus = FRAMESTATUS_FRAME_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED;
            goto lblCleanup;
        }

        hDll = VirtualAlloc(NULL, ptHeader->SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
        if (!hDll)
        {
            eStatus = FRAMESTATUS_FRAME_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED;
            goto lblCleanup;
        }
    }

    *phDll = (HMODULE)hDll;
    hDll = NULL;

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    if (hDll)
    {
        VirtualFree(hDll, 0, MEM_RELEASE);
    }

    return eStatus;
}

FRAMESTATUS
frame_ProtectMemory(
    __in_req HMODULE hDll
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PIMAGE_SECTION_HEADER ptSection = NULL;
    PVOID pvSectionMemory = NULL;
    DWORD dwPermissions = 0;
    DWORD dwOldPermissions = 0;
    DWORD dwSectionCounter = 0;
    DWORD dwSectionCount = 0;

    ASSERT(hDll);

    ptSection = FRAME_SECTION_HEADER(hDll);
    dwSectionCount = FRAME_FILE_HEADER(hDll)->NumberOfSections;
    for (dwSectionCounter = 0; dwSectionCounter < dwSectionCount; dwSectionCounter++, ptSection++)
    {
        if (0 < ptSection->SizeOfRawData)
        {
            pvSectionMemory = PTR_ADD(hDll, ptSection->VirtualAddress);
            if (IMAGE_SCN_MEM_DISCARDABLE & ptSection->Characteristics)
            {
                if (!VirtualFree(pvSectionMemory, ptSection->Misc.VirtualSize, MEM_DECOMMIT))
                {
                    eStatus = FRAMESTATUS_FRAME_PROTECTMEMORY_VIRTUALFREE_FAILED;
                    goto lblCleanup;
                }
            }
            else
            {
                dwPermissions = frame_GetSectionPermissions(ptSection->Characteristics);
                if (!VirtualProtect(pvSectionMemory,
                                    min(ptSection->SizeOfRawData, ptSection->Misc.VirtualSize),
                                    dwPermissions,
                                    &dwOldPermissions))
                {
                    eStatus = FRAMESTATUS_FRAME_PROTECTMEMORY_VIRTUALPROTECT_FAILED;
                    goto lblCleanup;
                }
            }
        }
    }

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}

FRAMESTATUS
frame_MapImageData(
    __in PVOID pvImage,
    __inout HMODULE hDll
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PIMAGE_SECTION_HEADER ptSection = FRAME_SECTION_HEADER(pvImage);
    PIMAGE_OPTIONAL_HEADER ptOptionalHeader = FRAME_OPTIONAL_HEADER(pvImage);
    PIMAGE_FILE_HEADER ptFileHeader = FRAME_FILE_HEADER(pvImage);
    PVOID pvSectionVirtualAddress = NULL;
    DWORD cbSectionSize = 0;
    DWORD i = 0;

    ASSERT(pvImage);
    ASSERT(hDll);

    hDll = VirtualAlloc(hDll, ptOptionalHeader->SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
    if (!hDll)
    {
        eStatus = FRAMESTATUS_FRAME_MAPIMAGEDATA_PEHEADERS_VIRTUALALLOC_FAILED;
        goto lblCleanup;
    }

    // Map the PE headers
    CopyMemory(hDll, pvImage, ptOptionalHeader->SizeOfHeaders);

    // Map sections
    for (i = 0; i < ptFileHeader->NumberOfSections; ptSection++, i++)
    {
        pvSectionVirtualAddress = PTR_ADD(hDll, ptSection->VirtualAddress);
        cbSectionSize = ptSection->SizeOfRawData ? ptSection->SizeOfRawData : ptSection->Misc.VirtualSize;
        if(!VirtualAlloc(pvSectionVirtualAddress, cbSectionSize, MEM_COMMIT, PAGE_READWRITE))
        {
            eStatus = FRAMESTATUS_FRAME_MAPIMAGEDATA_SECTION_VIRTUALALLOC_FAILED;
            goto lblCleanup;
        }

        if (ptSection->SizeOfRawData)
        {
            CopyMemory(pvSectionVirtualAddress, PTR_ADD(pvImage, ptSection->PointerToRawData), cbSectionSize);
        }
    }

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}

FRAMESTATUS
frame_LoadExternalSymbols(
    __in_req HMODULE hDll
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PIMAGE_DATA_DIRECTORY ptImports = NULL;
    PIMAGE_IMPORT_DESCRIPTOR ptImportDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME ptData = NULL;
    PIMAGE_THUNK_DATA ptName = NULL;
    PIMAGE_THUNK_DATA ptSymbol = NULL;
    HMODULE hLibrary = NULL;

    ASSERT(hDll);

    ptImports = FRAME_DATA_DIRECTORY_ENTRY(hDll, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!ptImports->Size)
    {
        eStatus = FRAMESTATUS_SUCCESS;
        goto lblCleanup;
    }

    for (ptImportDescriptor = PTR_ADD(hDll, ptImports->VirtualAddress);
         ptImportDescriptor->Characteristics;
         ptImportDescriptor++)
    {
        hLibrary = LoadLibraryA((PCHAR)PTR_ADD(hDll, ptImportDescriptor->Name));
        if (!hLibrary)
        {
            eStatus = FRAMESTATUS_FRAME_LOADEXTERNALSYMBOLS_LOADLIBRARYA_FAILED;
            goto lblCleanup;
        }

        ptName = (PIMAGE_THUNK_DATA)PTR_ADD(hDll, ptImportDescriptor->OriginalFirstThunk);
        ptSymbol = (PIMAGE_THUNK_DATA)PTR_ADD(hDll, ptImportDescriptor->FirstThunk);
        for (; ptName->u1.Function; ptName++, ptSymbol++)
        {
            // Import symbols from the loaded library
            ptData = (PIMAGE_IMPORT_BY_NAME)PTR_ADD(hDll, ptName->u1.AddressOfData);
            ptSymbol->u1.Function = (SIZE_T)GetProcAddress(hLibrary, (LPCSTR)ptData->Name);
            if (!ptSymbol->u1.Function)
            {
                eStatus = FRAMESTATUS_FRAME_LOADEXTERNALSYMBOLS_GETPROCADDRESS_FAILED;
                goto lblCleanup;
            }
        }
    }

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}

FRAMESTATUS
frame_RelocateSymbols(
    __in_req HMODULE hDll,
    __in SIZE_T cbRelocationDelta
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PIMAGE_BASE_RELOCATION ptRelocationBlock = NULL;
    PIMAGE_DATA_DIRECTORY ptRelocationData = NULL;
    PVOID pvPageRVA = NULL;
    PSIZE_T pcbReference = NULL;
    PWORD pwRelocationEntry = 0;
    DWORD dwRelocationCount = 0;
    DWORD dwRelocationCounter = 0;
    DWORD cbBytesRead = 0;

    ASSERT(hDll);

    if (!cbRelocationDelta)
    {
        eStatus = FRAMESTATUS_SUCCESS;
        goto lblCleanup;
    }

    ptRelocationData = FRAME_DATA_DIRECTORY_ENTRY(hDll, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    ptRelocationBlock = (PIMAGE_BASE_RELOCATION)PTR_ADD(hDll, ptRelocationData->VirtualAddress);
    for (cbBytesRead = 0;
         cbBytesRead < ptRelocationData->Size;
         cbBytesRead += ptRelocationBlock->SizeOfBlock, ptRelocationBlock = (PIMAGE_BASE_RELOCATION)pwRelocationEntry)
    {
        pvPageRVA = PTR_ADD(hDll, ptRelocationBlock->VirtualAddress);
        dwRelocationCount = (ptRelocationBlock->SizeOfBlock - sizeof(*ptRelocationBlock)) / sizeof(WORD);
        pwRelocationEntry = (PWORD)PTR_ADD(ptRelocationBlock, sizeof(*ptRelocationBlock));

        // Perform Relocations
        for (dwRelocationCounter = 0;
             dwRelocationCounter < dwRelocationCount;
             dwRelocationCounter++, pwRelocationEntry++)
        {
            switch (FRAME_RELOCATION_TYPE(*pwRelocationEntry))
            {
            case IMAGE_REL_BASED_HIGHLOW:
            case IMAGE_REL_BASED_DIR64:
                pcbReference = (PSIZE_T)PTR_ADD(pvPageRVA, FRAME_RELOCATION_OFFSET(*pwRelocationEntry));
                *pcbReference += cbRelocationDelta;
                break;
            case IMAGE_REL_BASED_ABSOLUTE:
                continue;
            default:
                eStatus = FRAMESTATUS_FRAME_RELOCATESYMBOLS_INVALID_RELOCATION_TYPE;
                goto lblCleanup;
            }
        }
    }

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}

VOID
frame_FreeExternalLibraries(
    __in_req HMODULE hDll
)
{
    PIMAGE_IMPORT_DESCRIPTOR ptImportDescriptor = NULL;
    PIMAGE_DATA_DIRECTORY ptDataDirectory = NULL;
    HMODULE hLibrary = NULL;

    ASSERT(hDll);

    ptDataDirectory = FRAME_DATA_DIRECTORY_ENTRY(hDll, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (!ptDataDirectory)
    {
        ptImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)PTR_ADD(hDll, ptDataDirectory->VirtualAddress);
        for (; ptImportDescriptor->Characteristics; ptImportDescriptor++)
        {
            hLibrary = GetModuleHandleA((PCHAR)PTR_ADD(hDll, ptImportDescriptor->Name));
            if (!hLibrary)
            {
                continue;
            }

            (VOID)FreeLibrary(hLibrary);
        }
    }
}

FRAMESTATUS
frame_GetOrdinalFromName(
    __in_req HMODULE hDll,
    __in_req PCSTR pszName,
    __out PWORD pwOrdinal
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PSTR pszExportName = NULL;
    PDWORD pdwNamePointer = NULL;
    PWORD pwExportsOrdinalTable = NULL;
    DWORD dwNameIndex = 0;
    PIMAGE_EXPORT_DIRECTORY ptExportDirectory = NULL;

    ASSERT(hDll);
    ASSERT(pszName);

    ptExportDirectory = FRAME_DATA_DIRECTORY(hDll, IMAGE_DIRECTORY_ENTRY_EXPORT);
    pdwNamePointer = PTR_ADD(hDll, ptExportDirectory->AddressOfNames);
    for (dwNameIndex = 0; dwNameIndex < ptExportDirectory->NumberOfFunctions; dwNameIndex++)
    {
        pszExportName = PTR_ADD(hDll, *pdwNamePointer);
        if (strncmp(pszName, pszExportName, MAX_PROC_NAME_SIZE) == 0)
        {
            break;
        }
    }

    if (dwNameIndex >= ptExportDirectory->NumberOfFunctions)
    {
        eStatus = FRAMESTATUS_LOADERGETORDINALFROMNAME_NAME_NOT_FOUND;
        goto lblCleanup;
    }

    pwExportsOrdinalTable = PTR_ADD(hDll, ptExportDirectory->AddressOfNameOrdinals);
    *pwOrdinal = (WORD)(pwExportsOrdinalTable[dwNameIndex] + ptExportDirectory->Base);

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}

FARPROC
frame_GetProcByOrdinal(
    __in_req HMODULE hDll,
    __in WORD wOrdinal
)
{
    PIMAGE_EXPORT_DIRECTORY ptExportDirectory = NULL;
    SIZE_T cbProcRVA = 0;
    PDWORD pdwFunctionRVAs = NULL;
    SIZE_T nProcIndex = 0;
    FARPROC pfnProc = NULL;

    ASSERT(hDll);

    ptExportDirectory = FRAME_DATA_DIRECTORY(hDll, IMAGE_DIRECTORY_ENTRY_EXPORT);
    nProcIndex = wOrdinal - ptExportDirectory->Base;
    if (!ptExportDirectory->NumberOfFunctions && nProcIndex < ptExportDirectory->NumberOfFunctions)
    {
        pdwFunctionRVAs = PTR_ADD(hDll, ptExportDirectory->AddressOfFunctions);
        cbProcRVA = (SIZE_T)pdwFunctionRVAs[nProcIndex];
        pfnProc = (FARPROC)(INT_PTR)PTR_ADD(hDll, cbProcRVA);
    }

    return pfnProc;
}

FRAMESTATUS
frame_CallEntryPoint(
    __in_req HMODULE hDll,
    __in DWORD dwReason
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_SUCCESS;
    PFNDLLMAIN pfnEntryPoint = NULL;
    PIMAGE_OPTIONAL_HEADER ptHeader = FRAME_OPTIONAL_HEADER(hDll);

    ASSERT(NULL != hDll);

    if (ptHeader->AddressOfEntryPoint)
    {
        pfnEntryPoint = (PFNDLLMAIN)(DWORD_PTR)PTR_ADD(hDll, ptHeader->AddressOfEntryPoint);
        if(!pfnEntryPoint((HINSTANCE)hDll, dwReason, 0))
        {
            eStatus = FRAMESTATUS_FRAME_CALLENTRYPOINT_ENTRYPOINT_FAILED;
        }
    }

    return eStatus;
}

FRAMESTATUS
FRAME_LoadLibraryEx(
    __in PVOID pvImage,
    __in DWORD dwFlags,
    __deref_out HMODULE *phDll
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    PIMAGE_OPTIONAL_HEADER ptOptionalHeader = NULL;
    HMODULE hDll = NULL;
    SIZE_T cbRelocationDelta = 0;

    if (!pvImage || !phDll)
    {
        eStatus = FRAMESTATUS_FRAME_LOADLIBRARY_INVALID_PARAMETERS;
        goto lblCleanup;
    }

    eStatus = frame_AllocateImageMemory(pvImage, (FRAME_NO_RELOCATION & dwFlags), &hDll);
    if (FRAME_FAILED(eStatus))
    {
        goto lblCleanup;
    }

    cbRelocationDelta = (SIZE_T)PTR_SUB(hDll, FRAME_OPTIONAL_HEADER(pvImage)->ImageBase);
    eStatus = frame_MapImageData(pvImage, hDll);
    if (FRAME_FAILED(eStatus))
    {
        goto lblCleanup;
    }

    if (FRAME_NO_ENTRY_POINT & dwFlags)
    {
        ptOptionalHeader = FRAME_OPTIONAL_HEADER(hDll);
        ptOptionalHeader->AddressOfEntryPoint = 0;
    }

    if (cbRelocationDelta)
    {
        eStatus = frame_RelocateSymbols(hDll, cbRelocationDelta);
        if (FRAME_FAILED(eStatus))
        {
            goto lblCleanup;
        }
    }

    eStatus = frame_LoadExternalSymbols(hDll);
    if (FRAME_FAILED(eStatus))
    {
        goto lblCleanup;
    }

    eStatus = frame_ProtectMemory(hDll);
    if (FRAME_FAILED(eStatus))
    {
        goto lblCleanup;
    }

    eStatus = frame_CallEntryPoint(hDll, DLL_PROCESS_ATTACH);
    if (FRAME_FAILED(eStatus))
    {
        FRAME_FreeLibrary(hDll);
        goto lblCleanup;
    }

    *phDll = hDll;
    hDll = NULL;

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}

FRAMESTATUS
FRAME_LoadLibrary(
    __in PVOID pvDll,
    __deref_out HMODULE *phDll
)
{
    return FRAME_LoadLibraryEx(pvDll, 0, phDll);
}

VOID
FRAME_FreeLibrary(
    __in_req HMODULE hDll
)
{
    if (hDll)
    {
        frame_CallEntryPoint(hDll, DLL_PROCESS_DETACH);
        frame_FreeExternalLibraries(hDll);
        VirtualFree((PVOID)hDll, 0, MEM_RELEASE);
    }
}

FRAMESTATUS
FRAME_GetProcAddress(
    __in_req HMODULE hDll,
    __in_req LPCSTR pszProcName,
    __out FARPROC *pfnProc
)
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    WORD wOrdinal = 0;

    if (!hDll || !pszProcName || !pfnProc)
    {
        eStatus = FRAMESTATUS_FRAME_GETPROCADDRESS_INVALID_PARAMETERS;
        goto lblCleanup;
    }

    if (!IS_INTRESOURCE(pszProcName))
    {
        eStatus = frame_GetOrdinalFromName(hDll, pszProcName, &wOrdinal);
        if (FRAME_FAILED(eStatus))
        {
            goto lblCleanup;
        }
    }
    else
    {
        wOrdinal = GET_INT_RESOURCE(pszProcName);
    }

    *pfnProc = frame_GetProcByOrdinal(hDll, wOrdinal);
    if (!*pfnProc)
    {
        eStatus = FRAMESTATUS_FRAME_GETPROCADDRESS_PROC_NOT_FOUND;
        goto lblCleanup;
    }

    eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
    return eStatus;
}
