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
	Function	:	loader_GetSectionPermissions
**********************************************************************************************************************/
DWORD
loader_GetSectionPermissions(
	__in DWORD dwSectionCharacteristics
)
{
	DWORD dwSimpleCharacteristics = (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE) & dwSectionCharacteristics;
	DWORD dwPermissions = 0;

	switch (dwSimpleCharacteristics)
	{
	case IMAGE_SCN_MEM_READ:
		dwPermissions = PAGE_READONLY;
		break;

	case IMAGE_SCN_MEM_WRITE:
		dwPermissions = PAGE_WRITECOPY;
		break;

	case IMAGE_SCN_MEM_EXECUTE:
		dwPermissions = PAGE_EXECUTE;
		break;

	case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE):
		dwPermissions = PAGE_READWRITE;
		break;

	case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE):
		dwPermissions = PAGE_EXECUTE_READ;
		break;

	case (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE):
		dwPermissions = PAGE_EXECUTE_WRITECOPY;
		break;

	case (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE):
		dwPermissions = PAGE_EXECUTE_READWRITE;
		break;

	default:
		dwPermissions = PAGE_NOACCESS;
	}

	return dwPermissions;
}

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

	hDll = VirtualAlloc((PVOID)ptHeader->ImageBase, ptHeader->SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
	if (NULL == hDll)
	{
		hDll = VirtualAlloc(NULL, ptHeader->SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
		if (NULL == hDll)
		{
			eStatus = FRAMESTATUS_LOADER_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED;
			goto lblCleanup;
		}
	}

	*phDll = (HMODULE)hDll;
	hDll = NULL;

	eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
	if (NULL != hDll)
	{
		(VOID)VirtualFree(hDll, 0, MEM_RELEASE);
	}

	return eStatus;
}

/**********************************************************************************************************************
	Function	:	loader_ProtectMemory	
**********************************************************************************************************************/
FRAMESTATUS
loader_ProtectMemory(
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

	ASSERT(NULL != hDll);

	ptSection = FRAME_SECTION_HEADER(hDll);
	dwSectionCount = FRAME_FILE_HEADER(hDll)->NumberOfSections;

	for (dwSectionCounter = 0; dwSectionCounter < dwSectionCount; dwSectionCounter++, ptSection++)
	{
		if (0 < ptSection->SizeOfRawData)
		{
			pvSectionMemory = ADD_POINTERS(hDll, ptSection->VirtualAddress);

			if (IMAGE_SCN_MEM_DISCARDABLE & ptSection->Characteristics)
			{
				if (!VirtualFree(pvSectionMemory, ptSection->Misc.VirtualSize, MEM_DECOMMIT))
				{
					eStatus = FRAMESTATUS_LOADER_PROTECTMEMORY_VIRTUALFREE_FAILED;
					goto lblCleanup;
				}
			}

			else
			{
				dwPermissions = loader_GetSectionPermissions(ptSection->Characteristics);

				if (!VirtualProtect(
					pvSectionMemory,
					min(ptSection->SizeOfRawData, ptSection->Misc.VirtualSize),
					dwPermissions,
					&dwOldPermissions))
				{
					eStatus = FRAMESTATUS_LOADER_PROTECTMEMORY_VIRTUALPROTECT_FAILED;
					goto lblCleanup;
				}
			}
		}
	}

	eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
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
	PIMAGE_SECTION_HEADER ptSection = FRAME_SECTION_HEADER(pvImage);
	PIMAGE_OPTIONAL_HEADER ptOptionalHeader = FRAME_OPTIONAL_HEADER(pvImage);
	PIMAGE_FILE_HEADER ptFileHeader = FRAME_FILE_HEADER(pvImage);
	PVOID pvSectionVirtualAddress = NULL;
	DWORD cbSectionSize = 0;
	DWORD i = 0;

	ASSERT(NULL != pvImage);
	ASSERT(NULL != hDll);

	hDll = VirtualAlloc(hDll, ptOptionalHeader->SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
	if (NULL == hDll)
	{
		eStatus = FRAMESTATUS_LOADER_MAPIMAGEDATA_PEHEADERS_VIRTUALALLOC_FAILED;
		goto lblCleanup;
	}

	// Map the PE headers
	CopyMemory(hDll, pvImage, ptOptionalHeader->SizeOfHeaders);

	for (i = 0; i < ptFileHeader->NumberOfSections; ptSection++, i++)
	{
		pvSectionVirtualAddress = ADD_POINTERS(hDll, ptSection->VirtualAddress);

		if (0 == ptSection->SizeOfRawData)
		{
			cbSectionSize = ptSection->Misc.VirtualSize;
		}

		else
		{
			cbSectionSize = ptSection->SizeOfRawData;
		}

		if(NULL == VirtualAlloc(pvSectionVirtualAddress, cbSectionSize, MEM_COMMIT, PAGE_READWRITE))
		{
			eStatus = FRAMESTATUS_LOADER_MAPIMAGEDATA_SECTION_VIRTUALALLOC_FAILED;
			goto lblCleanup;
		}

		if (0 != ptSection->SizeOfRawData)
		{
			CopyMemory(pvSectionVirtualAddress, ADD_POINTERS(pvImage, ptSection->PointerToRawData), cbSectionSize);
		}
	}

	eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
	return eStatus;
}

/**********************************************************************************************************************
	Function	:	loader_LoadExternalSymbols
**********************************************************************************************************************/
FRAMESTATUS
loader_LoadExternalSymbols(
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
	DWORD dwLibraryCounter = 0;

	ASSERT(NULL != hDll);

	ptImports = FRAME_DATA_DIRECTORY(hDll, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (0 == ptImports->Size)
	{
		eStatus = FRAMESTATUS_SUCCESS;
		goto lblCleanup;
	}

	for (ptImportDescriptor = ADD_POINTERS(hDll, ptImports->VirtualAddress);
		0 != ptImportDescriptor->Characteristics;
		ptImportDescriptor++)
	{
		hLibrary = LoadLibraryA((PCHAR)ADD_POINTERS(hDll, ptImportDescriptor->Name));
		if (NULL == hLibrary)
		{
			eStatus = FRAMESTATUS_LOADER_LOADEXTERNALSYMBOLS_LOADLIBRARYA_FAILED;
			goto lblCleanup;
		}
		dwLibraryCounter++;

		ptName = (PIMAGE_THUNK_DATA)ADD_POINTERS(hDll, ptImportDescriptor->OriginalFirstThunk);
		ptSymbol = (PIMAGE_THUNK_DATA)ADD_POINTERS(hDll, ptImportDescriptor->FirstThunk); 

		for	(; 0 != ptName->u1.Function; ptName++, ptSymbol++)
		{
			// Import symbols from the loaded library
			ptData = (PIMAGE_IMPORT_BY_NAME)ADD_POINTERS(hDll, ptName->u1.AddressOfData);
			ptSymbol->u1.Function = (SIZE_T)GetProcAddress(hLibrary, (LPCSTR)ptData->Name);
			if (0 == ptSymbol->u1.Function)
			{
				eStatus = FRAMESTATUS_LOADER_LOADEXTERNALSYMBOLS_GETPROCADDRESS_FAILED;
				goto lblCleanup;
			}
		}
	}

	eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
	return eStatus;
}

/**********************************************************************************************************************
	Function	:	loader_RelocateSymbols
**********************************************************************************************************************/
FRAMESTATUS
loader_RelocateSymbols(
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

	ASSERT(NULL != hDll);

	if (0 == cbRelocationDelta)
	{
		eStatus = FRAMESTATUS_SUCCESS;
		goto lblCleanup;
	}

	ptRelocationData = FRAME_DATA_DIRECTORY(hDll, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	ptRelocationBlock = (PIMAGE_BASE_RELOCATION)ADD_POINTERS(hDll, ptRelocationData->VirtualAddress);

	for (cbBytesRead = 0; cbBytesRead < ptRelocationData->Size; cbBytesRead += ptRelocationBlock->SizeOfBlock,
		ptRelocationBlock = (PIMAGE_BASE_RELOCATION)pwRelocationEntry)
	{
		pvPageRVA = ADD_POINTERS(hDll, ptRelocationBlock->VirtualAddress);
		dwRelocationCount = (ptRelocationBlock->SizeOfBlock - sizeof(*ptRelocationBlock)) / sizeof(WORD);
		pwRelocationEntry = (PWORD)ADD_POINTERS(ptRelocationBlock, sizeof(*ptRelocationBlock));

		// Perform Relocations
		for (dwRelocationCounter = 0; dwRelocationCounter < dwRelocationCount; dwRelocationCounter++, pwRelocationEntry++)
		{
			switch (FRAME_RELOCATION_TYPE(*pwRelocationEntry))
			{
			case IMAGE_REL_BASED_HIGHLOW:
				__fallthrough;

			case IMAGE_REL_BASED_DIR64:
				pcbReference = (PSIZE_T)ADD_POINTERS(pvPageRVA, FRAME_RELOCATION_OFFSET(*pwRelocationEntry));
				*pcbReference += cbRelocationDelta;
				break;

			case IMAGE_REL_BASED_ABSOLUTE:
				continue;

			default:
				eStatus = FRAMESTATUS_LOADER_RELOCATESYMBOLS_INVALID_RELOCATION_TYPE;
				goto lblCleanup;
			}	
		}
	}

	eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
	return eStatus;
}

/**********************************************************************************************************************
	Function	:	loader_FreeExternalLibraries
**********************************************************************************************************************/
VOID
loader_FreeExternalLibraries(
	__in_req HMODULE hDll
)
{
	PIMAGE_IMPORT_DESCRIPTOR ptImportDescriptor = NULL;
	PIMAGE_DATA_DIRECTORY ptDataDirectory = NULL;
	HMODULE hLibrary = NULL;

	ASSERT(NULL != hDll);

	ptDataDirectory = FRAME_DATA_DIRECTORY(hDll, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (NULL != ptDataDirectory)
	{
		ptImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)ADD_POINTERS(hDll, ptDataDirectory->VirtualAddress);
		for (; 0 != ptImportDescriptor->Characteristics; ptImportDescriptor++)
		{
			hLibrary = GetModuleHandleA((PCHAR)ADD_POINTERS(hDll, ptImportDescriptor->Name));
			if (NULL == hLibrary)
			{
				continue;
			}

			(VOID)FreeLibrary(hLibrary);
		}
	}
}

/**********************************************************************************************************************
	Function	:	loader_CallEntryPoint
**********************************************************************************************************************/
FRAMESTATUS
loader_CallEntryPoint(
	__in_req HMODULE hDll,
	__in DWORD dwReason
)
{
	FRAMESTATUS eStatus = FRAMESTATUS_SUCCESS;
	PFNENTRYPOINT pfnEntryPoint = NULL;
	PIMAGE_OPTIONAL_HEADER ptHeader = FRAME_OPTIONAL_HEADER(hDll);

	ASSERT(NULL != hDll);

	if (0 != ptHeader->AddressOfEntryPoint)
	{
		pfnEntryPoint = (PFNENTRYPOINT)(DWORD_PTR)ADD_POINTERS(hDll, ptHeader->AddressOfEntryPoint);
		if(!pfnEntryPoint((HINSTANCE)hDll, dwReason, 0))
		{
			eStatus = FRAMESTATUS_LOADER_CALLENTRYPOINT_ENTRYPOINT_FAILED;
		}
	}

	return eStatus;
}

/**********************************************************************************************************************
	Function	:	LOADER_LoadLibrary
**********************************************************************************************************************/
FRAMESTATUS
LOADER_LoadLibrary(
	__in PVOID pvImage,
	__deref_out HMODULE *phDll
)
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
	HMODULE hDll = NULL;
	SIZE_T cbRelocationDelta = 0;

	if ((NULL == pvImage) || (NULL == phDll))
	{
		eStatus = FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS;
		goto lblCleanup;
	}

	eStatus = loader_AllocateImageMemory(pvImage, &hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

	cbRelocationDelta = (SIZE_T)SUB_POINTERS(hDll, FRAME_OPTIONAL_HEADER(pvImage)->ImageBase);

	eStatus = loader_MapImageData(pvImage, hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

	if (0 != cbRelocationDelta)
	{
		eStatus = loader_RelocateSymbols(hDll, cbRelocationDelta);
		if (FRAME_FAILED(eStatus))
		{
			goto lblCleanup;	
		}
	}

	eStatus = loader_LoadExternalSymbols(hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

	eStatus = loader_ProtectMemory(hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

	eStatus = loader_CallEntryPoint(hDll, DLL_PROCESS_ATTACH);
	if (FRAME_FAILED(eStatus))
	{
		LOADER_FreeLibrary(hDll);
		goto lblCleanup;	
	}

	*phDll = hDll;
	hDll = NULL;

	eStatus = FRAMESTATUS_SUCCESS;

lblCleanup:
	return eStatus;
}

/**********************************************************************************************************************
	Function	:	LOADER_FreeLibrary
**********************************************************************************************************************/
VOID
LOADER_FreeLibrary(
	__in_req HMODULE hDll
)
{
	if (NULL != hDll)
	{
		loader_CallEntryPoint(hDll, DLL_PROCESS_DETACH);

		loader_FreeExternalLibraries(hDll);
		(VOID)VirtualFree((PVOID)hDll, 0, MEM_RELEASE);
	}	
}