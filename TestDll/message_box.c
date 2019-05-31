#include "message_box.h"

VOID MB_DisplayMessage(PTSTR pszMessage)
{
	(VOID)MessageBoxA(NULL, pszMessage, "DllTests", 0);
}
