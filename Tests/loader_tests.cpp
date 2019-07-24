#define CATCH_CONFIG_MAIN
#include <Catch2/catch.h>

#include "testing_common.h"
#include "headers.h"

extern "C"
{
#include "frame_status.h"
#include "loader.h"
#include "frame.h"
}

#ifdef _WIN64
const std::wstring dll_test_file = L"F:\\Projects\\Frame\\Bin\\TestDll\\x64\\TestDll.dll";
#else
const std::wstring dll_test_file = L"F:\\Projects\\Frame\\Bin\\TestDll\\x86\\TestDll.dll";
#endif

typedef VOID(*PFN_DISPLAY_MESSAGE)(PCSTR);

/*
TEST_CASE("Test FRAME_LoadLibrary invalid args", "[loader][loadlibrary]")
{
	FRAMESTATUS eStatus = FRAME_LoadLibrary(NULL, 0,NULL);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);

	eStatus = FRAME_LoadLibrary((PVOID)0x10101010,0, NULL);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);

	eStatus = FRAME_LoadLibrary(NULL, 0, (HMODULE*)0x10101010);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);
}

TEST_CASE("Test normal library loading", "[loader][loadlibrary]")
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
	HMODULE hDll = NULL;
	Buffer buffered_dll = read_file(dll_test_file);

	eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
	REQUIRE(FRAMESTATUS_SUCCESS == eStatus);
	REQUIRE_NOTHROW(FRAME_FreeLibrary(hDll));

	PVOID pvPlaceHolder = VirtualAlloc(
		(PVOID)FRAME_OPTIONAL_HEADER(buffered_dll.data())->ImageBase, 
		1, 
		MEM_RESERVE, 
		PAGE_READONLY);
	REQUIRE(NULL != pvPlaceHolder);

	eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
	REQUIRE(FRAMESTATUS_SUCCESS == eStatus);
	REQUIRE_NOTHROW(FRAME_FreeLibrary(hDll));

	VirtualFree(pvPlaceHolder, 0, MEM_RELEASE);
}
*/

TEST_CASE("Test the GetProcAddress function")
{
	FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
	HMODULE hDll = NULL;
	PFN_DISPLAY_MESSAGE proc = NULL;
	Buffer buffered_dll = read_file(dll_test_file);

	eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
	REQUIRE(FRAMESTATUS_SUCCESS == eStatus);

	eStatus = FRAME_GetProcAddress(hDll, "MB_DisplayMessage", (FARPROC*)&proc);
	REQUIRE(FRAMESTATUS_SUCCESS == eStatus);

	proc("Test");

	FRAME_FreeLibrary(hDll);
}

