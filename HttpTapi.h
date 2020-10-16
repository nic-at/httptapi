/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name: HttpTapi.h

--*/

#pragma once

#include <windows.h>
#include "tapi.h"
#include "tspi.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "resource.h"
#include "resrc1.h"
#include <initguid.h> 
#include <shlwapi.h>
#include <Wincrypt.h>
#include <Windowsx.h>

#include "Config.h"

//                                                                      
// Line device GUID of MSP                                                    
//                                                  
// CLSID = s '// 23F7C678- 24E1 -48db- AE AC- 54 A6 F2 A0 10 A0


//DEFINE_GUID(CLSID_SAMPMSP, 
//0x23F7C678, 0x24E1, 0x48db, 0xAE, 0xAC, 0x54, 0xA6, 0xF2, 0xA0, 0x10, 0xA0);

// {30A99BF3-079B-4f42-A00C-B7DD25689074}
DEFINE_GUID(CLSID_SAMPMSP, 
0x30a99bf3, 0x79b, 0x4f42, 0xa0, 0xc, 0xb7, 0xdd, 0x25, 0x68, 0x90, 0x74);


// DesKeyBlob:      A plaintext key BLOB stored in a byte array. The 
//                  byte array  must have the following format:
//                      BLOBHEADER hdr;
//                      DWORD dwKeySize;
//                      BYTE rgbKeyData [];

// Our DES Key with Parity
// 6e d3 86 79 94 04 6d c2
BYTE DesKeyBlob[] = {
    0x08,0x02,0x00,0x00,0x01,0x66,0x00,0x00, // BLOB header 
    0x08,0x00,0x00,0x00,                     // key length, in bytes
    0x6e,0xd3,0x86,0x79,0x94,0x04,0x6d,0xc2  // DES key with parity
};

#define MAX_REGKEYNAME_LENGTH   128
#define MAX_REGKEYVAL_LENGTH   1024
#define MAX_LICENSE_LENGTH     2048

#define CACERT_FILENAME "HTTPTAPI_TRUSTED_CAs.pem"
CHAR glpCAFileName[MAX_PATH];

typedef struct _DRVLINE
{
    HTAPILINE               htLine;
    LINEEVENT               pfnEventProc;
	// 
	// MSP Variables
	DWORD				    dwMSPHandle;
    HTAPIMSPLINE			htMSPLineHandle;
	//
    DWORD                   dwDeviceID;
    char                    szComm[8];
    HTAPICALL               htCall;
    DWORD                   dwCallState;
    DWORD                   dwCallStateMode;
    DWORD                   dwMediaMode;
    HANDLE                  hComm;
    BOOL                    bDropInProgress;
    OVERLAPPED              Overlapped;
} DRVLINE, FAR *PDRVLINE;


typedef struct _DRVLINECONFIG
{
    char                    szPort[8];
    char                    szUri[MAX_REGKEYVAL_LENGTH];
    char                    szCa[MAX_REGKEYVAL_LENGTH];
} DRVLINECONFIG, FAR *PDRVLINECONFIG;


typedef struct _ASYNC_REQUEST
{
    DWORD                   dwRequestID;
    DWORD                   dwCommand;
    char                    szCommand[32];
    struct _ASYNC_REQUEST  *pNext;
} ASYNC_REQUEST, *PASYNC_REQUEST;


typedef struct _LICENSE {
	char *licenseIdentifier;
	char *licenseVersion;
	int   iLicenseVersion;
	char *name;
	char *company;
	char *address;
	char *validUntil;
	char *numberOfLines;
	int   iNumberOfLines;
	char *additionalData;
} LICENSE, FAR *PLICENSE;

DWORD               gdwLineDeviceIDBase;
DWORD               gdwPermanentProviderID;
HANDLE              ghInst;
HPROVIDER           ghProvider;
ASYNC_COMPLETION    gpfnCompletionProc;
LINEEVENT           gpfnLineCreateProc;
DWORD				gdwNumberOfLines;	// Licensed lines
int                 giNumLines;			// Configured lines
int                 giUseWindowsCertStore;		// Use Windows Certificate Store
LICENSE				gLicense;
char *				gLicenseString;

// Location in the Registry to store our settings
char gszHttpTapiKey[]        = "HttpTapi";
//char gszHttpTapiKeyBase[]    = "Software\\ipcom.at";
//char gszHttpTapiKeyFull[]    = "Software\\ipcom.at\\HttpTapi";
char gszHttpTapiKeyBase[]    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Telephony";
char gszHttpTapiKeyFull[]    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Telephony\\HTTPTAPI";
// Registry key to store if Windows certificate store should be used
char gszHttpTapiCertStore[]   = "UseWindowsCertStore";
// Registry key to store the number of configured lines
char gszHttpTapiNumLines[]   = "NumLines";
// Registry key to store the license string
char gszHttpTapiLicense[]   = "License2";
char gszHttpTapiLicenseIdentifier[] = "www.ipcom.at/httptapi";
int  gszHttpTapiLicenseVersion = 1;
// Registry key which hold the debug level (0=off, 7=maximum debugging)
char gszHttpTapiDebugLevel[] = "HttpTapiDebugLevel";
// Default (sample) configuration
char gszHttpTapiDefLineConfigParamsName[] = "ext. 123 (SNOM 200)";
char gszHttpTapiDefLineConfigParamsUri[] = "http://1.1.1.1/?NUMBER=%N&DIAL=Dial&active_line=1";
char gszHttpTapiDefLineConfigParamsCa[] = "";

// Default strings
char gszDefaultSnomUri[] = "http://1.1.1.1/?NUMBER=%N&DIAL=Dial&active_line=1";
char gszDefaultAsteriskUri[] = "http://1.1.1.1:8088/asterisk/mxml?action=login&username=YOURUSERNAME&secret=YOURPASSWORD#http://1.1.1.1:8088/asterisk/mxml?action=originate&channel=SIP/YOURPEERNAME&context=YOURCONTEXT&exten=%N&priority=1&callerid=1234567&timeout=5000";

char gszhdLine[]       = "hdLine";
char gszhdCall[]       = "hdCall";
char gszdwSize[]       = "dwSize";
char gszhwndOwner[]    = "hwndOwner";
char gszdwDeviceID[]   = "dwDeviceID";
char gszdwRequestID[]  = "dwRequestID";
char gszlpCallParams[] = "lpCallParams";
char gszdwPermanentProviderID[] = "dwPermanentProviderID";


LPWSTR
PASCAL
My_lstrcpyW(
    WCHAR   *pString1,
    WCHAR   *pString2
    );

LPVOID
PASCAL
DrvAlloc(
    DWORD dwSize
    );

VOID
PASCAL
DrvFree(
    LPVOID lp
    );

void
PASCAL
SetCallState(
    PDRVLINE    pLine,
    DWORD       dwCallState,
    DWORD       dwCallStateMode
    );

BOOL
CALLBACK
ConfigDlgProc(
    HWND    hwnd,
    UINT    msg,
    WPARAM  wParam,
    LPARAM  lParam
    );

LONG
PASCAL
ProviderInstall(
    char   *pszProviderName,
    BOOL    bNoMultipleInstance
    );

void
PASCAL
DropActiveCall(
    PDRVLINE    pLine
    );
