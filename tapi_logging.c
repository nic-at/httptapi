/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name: tapi_logging.h

These functions are used for logging from a TSP.

--*/

#include <stdio.h>
#include "tapi_logging.h"

DWORD gdwDebugLevel = 0;
char gszTab[]          = "    ";

// We are using "insecure" string functions. But this 
// shouldn't be a problem, as we carefully check the number of characters
// and null-terminate them always!
#pragma warning (disable:4996)

void setLogLevel(DWORD level) {
	gdwDebugLevel = level;
}

DWORD getLogLevel() {
	return gdwDebugLevel;
}

#ifdef LOGGING

void PASCAL Prolog(PFUNC_INFO  pInfo)
{
    DWORD i;

    LOG((3, "%s: enter", pInfo->lpszFuncName));

    for (i = 0; i < pInfo->dwNumParams; i++)
    {
        if (pInfo->aParams[i].dwVal &&
            pInfo->aParams[i].lpszVal[3] == 'z') // lpszVal = "lpsz..."
        {
            LOG((3, "%s%s=x%lx, '%s'",
                gszTab,
                pInfo->aParams[i].lpszVal,
                pInfo->aParams[i].dwVal,
                pInfo->aParams[i].dwVal
                ));
        } else {
            LOG((3, "%s%s=x%lx",
                gszTab,
                pInfo->aParams[i].lpszVal,
                pInfo->aParams[i].dwVal
                ));
        }
    }
}

LONG PASCAL Epilog(PFUNC_INFO pInfo, LONG lResult)
{
    LOG((3, "%s: returning x%x", pInfo->lpszFuncName, lResult));
    return lResult;
}


void CDECL DebugOutput(
    DWORD   dwDbgLevel,
    LPCSTR  lpszFormat,
    ...
    )
{
    if (dwDbgLevel <= gdwDebugLevel)
    {
        char    buf[2048] = "HTTPTAPI: ";
        va_list ap;

        va_start(ap, lpszFormat);
		// buff - "HTTPTAPI: " - \r\n - \0
		if (_vsnprintf(&buf[10], 2048 - 10 -   2   -  1, lpszFormat, ap ) == -1) {
			buf[2046] = '\0';
		}
		buf[strlen(buf)] = '\r';
		buf[strlen(buf)+1] = '\n';
		buf[strlen(buf)+2] = '\0';

        OutputDebugString (buf);

        va_end(ap);

#ifdef LOGFILENAME
	{
		// log also to file
		DWORD writecount;
		SYSTEMTIME systemTime;
        char timestamp[128];

		HANDLE h = CreateFile(LOGFILENAME, GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (h != INVALID_HANDLE_VALUE) {
			GetLocalTime(&systemTime);
			_snprintf(timestamp, sizeof(timestamp), "%d-%02d-%02d %02d:%02d:%02d.%03d: ",
				systemTime.wYear,
				systemTime.wMonth,
				systemTime.wDay,
				systemTime.wHour,
				systemTime.wMinute,
				systemTime.wSecond,
				systemTime.wMilliseconds);
			timestamp[sizeof(timestamp)-1] = '\0';
			SetFilePointer(h, 0, 0, FILE_END);
			//strlen's size_t may be greater than WriteFile's DWORD (eg on 64bit machines)
			//but the log messages will never be that long, this we can cast and ignore the warning
			WriteFile(h, timestamp, (DWORD) strlen(timestamp), &writecount, 0);
			WriteFile(h, buf, (DWORD) strlen(buf), &writecount, 0);
			CloseHandle(h);
		}
	}
#endif

	}

}

#endif
