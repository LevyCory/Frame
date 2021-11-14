#define CATCH_CONFIG_MAIN
#include <Catch2/include/catch.hpp>

#include "testing_common.h"
#include "common.h"
#include "event.hpp"

extern "C"
{
    #include "frame_status.h"
    #include "frame.h"
}

#ifdef _WIN64
static const std::wstring dll_test_file = L"..\\Bin\\TestDll\\x64\\TestDll.dll";
#else
static const std::wstring dll_test_file = L"..\\Bin\\TestDll\\x86\\TestDll.dll";
#endif

const std::string event_name = "TestEvent";
Buffer buffered_dll = read_file(dll_test_file);
Event test_event(event_name, true, true);

typedef VOID(*PFN_DISPLAY_MESSAGE)(PCSTR);

TEST_CASE("Test FRAME_LoadLibrary invalid args", "[loadlibrary]")
{
    FRAMESTATUS eStatus = FRAME_LoadLibrary(NULL, 0, NULL);
    REQUIRE(FRAMESTATUS_FRAME_LOADLIBRARY_INVALID_PARAMETERS == eStatus);

    eStatus = FRAME_LoadLibrary((PVOID)0x10101010,0, NULL);
    REQUIRE(FRAMESTATUS_FRAME_LOADLIBRARY_INVALID_PARAMETERS == eStatus);

    eStatus = FRAME_LoadLibrary(NULL, 0, (HMODULE*)0x10101010);
    REQUIRE(FRAMESTATUS_FRAME_LOADLIBRARY_INVALID_PARAMETERS == eStatus);
}

TEST_CASE("Test normal library loading", "[loadlibrary]")
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    HMODULE hDll = NULL;

    SECTION("Sanity")
    {
        eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
        REQUIRE(FRAME_SUCCESS(eStatus));
        REQUIRE(test_event.is_set());
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
        REQUIRE(FRAME_SUCCESS(eStatus));
        REQUIRE(test_event.is_set());

        VirtualFree(pvPlaceHolder, 0, MEM_RELEASE);
    }

    REQUIRE_NOTHROW(FRAME_FreeLibrary(hDll));
}

TEST_CASE("Test the GetProcAddress function", "[GetProcAddress]")
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    HMODULE hDll = NULL;
    PFN_DISPLAY_MESSAGE proc = NULL;

    eStatus = FRAME_LoadLibrary(buffered_dll.data(), 0, &hDll);
    REQUIRE(FRAME_SUCCESS(eStatus));

    SECTION("Get proc by name")
    {
        eStatus = FRAME_GetProcAddress(hDll, "SignalEvent", (FARPROC*)&proc);
        REQUIRE(FRAME_SUCCESS(eStatus));

        proc(event_name.c_str());
        REQUIRE(test_event.is_set());
    }

    SECTION("Get proc by ordinal")
    {
        eStatus = FRAME_GetProcAddress(hDll, (LPCSTR)1, (FARPROC*)&proc);
        REQUIRE(FRAME_SUCCESS(eStatus));

        proc(event_name.c_str());
        REQUIRE(test_event.is_set());
    }

    REQUIRE_NOTHROW(FRAME_FreeLibrary(hDll));
}

TEST_CASE("Test Frame's flags")
{
    FRAMESTATUS eStatus = FRAMESTATUS_INVALID;
    HMODULE hDll = NULL;
    PFN_DISPLAY_MESSAGE proc = NULL;

    test_event.reset();

    SECTION("FRAME_NO_DLLMAIN")
    {
        eStatus = FRAME_LoadLibrary(buffered_dll.data(), FRAME_NO_ENTRY_POINT, &hDll);
        REQUIRE(FRAME_SUCCESS(eStatus));
        REQUIRE(!test_event.is_set());
    }

    SECTION("FRAME_NO_RELOCATION")
    {
        PVOID pvPlaceHolder = VirtualAlloc(
            (PVOID)FRAME_OPTIONAL_HEADER(buffered_dll.data())->ImageBase,
            1,
            MEM_RESERVE,
            PAGE_READONLY);
            REQUIRE(NULL != pvPlaceHolder);

        eStatus = FRAME_LoadLibrary(buffered_dll.data(), FRAME_NO_RELOCATION, &hDll);
        REQUIRE(FRAMESTATUS_FRAME_ALLOCATEIMAGEMEMORY_VIRTUALALLOC_FAILED == eStatus);

        VirtualFree(pvPlaceHolder, 0, MEM_RELEASE);
    }

    REQUIRE_NOTHROW(FRAME_FreeLibrary(hDll));
}
