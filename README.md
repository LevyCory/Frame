# Frame
A simple loader that is able to load in-memory dll.

# Usage

```C
// Loading a dll from memory. pvDll being the in-memory dll.
HMODULE hDll = FRAME_LoadLibrary(pvDll);

// Getting the address of an exported function from the loaded dll.
FARPROC pfnProc = FRAME_GetProcAddress(hDll, "FunctionName");

// Freeing the dll
FRAME_FreeLibrary(hDll);
```
