#include <string>

#include <windows.h>

#include "signal_event.hpp"

BOOL
WINAPI 
DllMain( 
    HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);

    const std::string name{"TestEvent"};

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        SignalEvent(name.c_str());
        break;

    case DLL_PROCESS_DETACH:
        SignalEvent(name.c_str());
        break;
    }
    return TRUE;
}

