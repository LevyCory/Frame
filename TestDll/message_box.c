#include "message_box.h"

VOID MB_DisplayMessage(PSTR pszMessage)
{
	(VOID)MessageBoxA(NULL, pszMessage, "DllTests", 0);
}
