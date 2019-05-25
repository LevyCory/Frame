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
	DWORD dwPermissions = -1;

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

	case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
		dwPermissions = PAGE_READWRITE;
		break;

	case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE:
		dwPermissions = PAGE_EXECUTE_READ;
		break;

	case IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE:
		dwPermissions = PAGE_EXECUTE_WRITECOPY;
		break;

	case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE:
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

	hDll = VirtualAlloc(ptHeader->ImageBase, ptHeader->SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
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
	PIMAGE_SECTION_HEADER ptSection = FRAME_SECTION_HEADER(pvImage);
	PIMAGE_FILE_HEADER ptFileHeader = FRAME_FILE_HEADER(pvImage);
	PVOID pvImageBase = (PVOID)FRAME_OPTIONAL_HEADER(pvImage)->ImageBase;
	PVOID pvSectionVirtualAddress = NULL;
	DWORD i = 0;

	for (i = 0; i < ptFileHeader->NumberOfSections; ptSection++)
	{
		pvSectionVirtualAddress = ADD_POINTERS(pvImageBase, ptSection->VirtualAddress);

		if(!VirtualAlloc(
			pvSectionVirtualAddress,
			ptSection->SizeOfRawData,
			MEM_COMMIT,
			PAGE_READWRITE))
		{
			eStatus = FRAMESTATUS_LOADER_MAPIMAGEDATA_VIRTUALALLOC_FAILED;
			goto lblCleanup;
		}

		CopyMemory(pvSectionVirtualAddress, (PVOID)ptSection->PointerToRawData, ptSection->SizeOfRawData);
	}

lblCleanup:
	return eStatus;
}

/**********************************************************************************************************************
	Function	:	loader_ResolveImageImports
**********************************************************************************************************************/
FRAMESTATUS
loader_ResolveImageImports(
	__in_req PVOID pvImage,
	__in PVOID pvImageBase
)
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
	PIMAGE_IMPORT_DESCRIPTOR ptImportDescriptor = FRAME_IMPORT_LIST(pvImageBase, pvImage);
	PIMAGE_IMPORT_BY_NAME ptSymbolData = NULL;
	PSIZE_T pvName = NULL;
	PSIZE_T pvSymbol = NULL;
	HMODULE hLoadedLibrary = NULL;
	LPCSTR pszLibraryName = NULL;

	ASSERT(NULL != pvImage);

	for (; 0 != ptImportDescriptor->Characteristics; ptImportDescriptor++)
	{
		pszLibraryName = (LPCSTR)ADD_POINTERS(pvImageBase, ptImportDescriptor->Name);
		hLoadedLibrary = LoadLibraryA(pszLibraryName);
		if (NULL == hLoadedLibrary)
		{
			eStatus = FRAMESTATUS_LOADER_RESOLVEIMPORTS_LOADLIBRARY_FAILED;
			goto lblCleanup;
		}
		
		pvName = ADD_POINTERS(pvImageBase, ptImportDescriptor->OriginalFirstThunk);
		pvSymbol = ADD_POINTERS(pvImageBase, ptImportDescriptor->FirstThunk);

		for (; 0 != *(PSIZE_T)pvName; pvName++, pvSymbol++)
		{
			// TODO: Deref pvImage
			ptSymbolData = (PIMAGE_IMPORT_BY_NAME)ADD_POINTERS(pvImage, pvImage);
			*pvSymbol = (PSIZE_T)GetProcAddress(hLoadedLibrary, (LPCSTR)ptSymbolData->Name);
			if (NULL == pvSymbol)
			{
				eStatus = FRAMESTATUS_LOADER_RESOLVEIMPORTS_GETPROCADDRESS_FAILED;
				goto lblCleanup;
			}
		}
	}
lblCleanup:
	return eStatus;
}

/**********************************************************************************************************************
	Function	:	LOADER_LoadLibrary
**********************************************************************************************************************/
FRAMESTATUS
LOADER_LoadLibrary(
	__in PVOID pvImage,
	__deref_out PVOID pvDll
)
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
	HMODULE hDll = NULL;

	eStatus = loader_AllocateImageMemory(pvImage, &hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

	eStatus = loader_MapImageData(pvImage, hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

	eStatus = loader_ResolveImageImports(pvImage, (PVOID)hDll);
	if (FRAME_FAILED(eStatus))
	{
		goto lblCleanup;	
	}

lblCleanup:
	return eStatus;
}
