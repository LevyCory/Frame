#define CATCH_CONFIG_MAIN

#include <catch.h>
#include <frame_status.h>
#include <loader.h>

TEST_CASE("Test LOADER_LoadLibrary invalid args", "[loader]")
{
	FRAMESTATUS eStatus = LOADER_LoadLibrary(NULL, NULL);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);
}
