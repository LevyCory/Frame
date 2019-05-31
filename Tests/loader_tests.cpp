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


TEST_CASE("Test LOADER_LoadLibrary invalid args", "[loader][loadlibrary]")
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

	SECTION("Sanity")
	{
		eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
		REQUIRE(FRAMESTATUS_SUCCESS == eStatus);
		FRAME_FreeLibrary(hDll);
	}

	SECTION("Relocation")
	{
		PVOID pvPlaceHolder = VirtualAlloc(
			(PVOID)FRAME_OPTIONAL_HEADER(buffered_dll.data())->ImageBase, 
			1, 
			MEM_RESERVE, 
			PAGE_READONLY);
		REQUIRE(NULL != pvPlaceHolder);

		eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
		REQUIRE(FRAMESTATUS_SUCCESS == eStatus);
		FRAME_FreeLibrary(hDll);

		VirtualFree(pvPlaceHolder, 0, MEM_RELEASE);
	}
}


