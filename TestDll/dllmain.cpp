#include <windows.h>

extern "C"
{
	#include "message_box.h"
}

BOOL
WINAPI 
DllMain( 
	HMODULE hModule,
    DWORD  dwReason,
	LPVOID lpReserved
)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
		MB_DisplayMessage((PSTR)"DllMain Attach Called!");
		break;
    case DLL_PROCESS_DETACH:
		MB_DisplayMessage((PSTR)"DllMain Detach Called!");
        break;
    }
    return TRUE;
}

