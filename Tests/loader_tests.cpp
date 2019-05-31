#define CATCH_CONFIG_MAIN

#include <catch.h>
//#include <frame_status.h>
#include "frame.h"

/*
TEST_CASE("Test LOADER_LoadLibrary invalid args", "[loader]")
{
	FRAMESTATUS eStatus = FRAME_LoadLibrary(NULL, 0,NULL);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);

	eStatus = FRAME_LoadLibrary((PVOID)0x10101010,0, NULL);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);

	eStatus = FRAME_LoadLibrary(NULL, 0, (HMODULE*)0x10101010);
	REQUIRE(FRAMESTATUS_LOADER_LOADLIBRARY_INVALID_PARAMETERS == eStatus);
}*/

int main(int argc, char* argv[])
{
	return static_cast<int>(FRAME_LoadLibrary(nullptr, 0,nullptr));
}

