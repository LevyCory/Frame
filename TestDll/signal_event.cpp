#include "signal_event.hpp"

DWORD SignalEvent(PCSTR pszEventName)
{
	DWORD dwStatus = 0;
	HANDLE event = NULL;
	
	event = CreateEventA(NULL, true, true, pszEventName);
	if (NULL == event)
	{
		dwStatus = 1;
		goto lblCleanup;
	}

	if(!SetEvent(event))
	{
		dwStatus = 1;
		goto lblCleanup;
	}

lblCleanup:
	return dwStatus;
}


