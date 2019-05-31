#include <windows.h>

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
		MessageBoxW(NULL, L"DllMain Attach Called!", L"TestDll", 0);
		break;
    case DLL_PROCESS_DETACH:
		MessageBoxW(NULL, L"DllMain Attach Called!", L"TestDll", 0);
        break;
    }
    return TRUE;
}

