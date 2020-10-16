/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name: tapi_logging.h

These functions are used for logging from a TSP.

--*/

#pragma once

#include <windows.h>

#define LOGGING
#define LOGFILENAME	"c:\\httptapi.log"

void setLogLevel(DWORD);
DWORD getLogLevel();

#ifdef LOGGING
typedef struct _FUNC_PARAM
{
    char        *lpszVal;
    DWORD       dwVal;
} FUNC_PARAM, *PFUNC_PARAM;
#endif

typedef struct _FUNC_INFO
{
#ifdef LOGGING
    char        *lpszFuncName;
    DWORD       dwNumParams;
    PFUNC_PARAM aParams;
#endif
    LONG        lResult;
} FUNC_INFO, *PFUNC_INFO;

#ifdef LOGGING

void CDECL DebugOutput(
    DWORD   dwLevel,
    LPCSTR  lpszFormat,
    ...
    );

#define LOG(arg) DebugOutput arg

LONG PASCAL Epilog(
    PFUNC_INFO  pInfo,
    LONG        lResult
    );

void PASCAL Prolog(
    PFUNC_INFO  pInfo
    );

#else

#define LOG(arg)
#define Epilog(pAsyncRequestInfo, lResult) (lResult)
#define Prolog(pAsyncRequestInfo)

#endif
