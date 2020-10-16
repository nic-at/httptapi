/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name: HttpTapi.c

--*/


#define _WIN32_WINNT 0x0400

// TSPI uses UNICODE (WCHAR). Other APIs (Debug, Registry, GUI) are generic (e.g. lpcTstr)
// and map to wide or ANSI dependent if UNICODE is defined or not.
// As the ATSP sample uses ANSI strings we also use ANSI, thus UNICODE will be not defined!
// Thus, we do manual WCHAR-ANSI conversion for strings exchanged with TSPI.

#ifdef UNICODE
  #error UNICODE is defined, but HttpTapi supports only ANSI mode! Undefine UNICODE!
#endif

#define TAPI_CURRENT_VERSION 0x00030000
#include "HttpTapi.h"
#include "tapi_logging.h"
#include "ExportCertificates.h"

#include <curl\curl.h>

/* *** decryptLicense ***
 * return values:
 *   0: OK
 *   1: memory allocation error
 *   2: invalid number of elements
 *   3: wrong license identifier
 *   4: wrong license version number
 *   5: bad number of lines
 *   6: error parsing additional data
 *   7: error in CSP acquiration
 *   8: error in decryption
 */
DWORD decryptLicense(PLICENSE pLicense, char *szencryptedLicense) {
	DWORD bufflen;
	char *buff, *buffbackup, *next;
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;

	LOG((5,"License: decrypting license ..."));

	CryptStringToBinary(
		szencryptedLicense,
		0,
		CRYPT_STRING_BASE64,
		0,
		&bufflen,
		0,
		0);

	if ( !(buff = (char *) DrvAlloc(bufflen*sizeof(BYTE) + 1)) ) {
		return 1;
	}

	CryptStringToBinary(
		szencryptedLicense,
		0,
		CRYPT_STRING_BASE64,
		(BYTE *) buff,
		&bufflen,
		0,
		0);


	// Acquire a handle to the CSP.

	if(!CryptAcquireContext(
		&hProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		// If the key container cannot be opened, try creating a new
		// container by specifying a container name and setting the 
		// CRYPT_NEWKEYSET flag.
		if(NTE_BAD_KEYSET == GetLastError())
		{
			if(!CryptAcquireContext(
				&hProv,
				"mytestcontainer",
				MS_ENHANCED_PROV,
				PROV_RSA_FULL,
				CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT))
			{
				LOG((1,"License: Error in AcquireContext 0x%08x",GetLastError()));
				if (buff) DrvFree(buff);
				return 7;
			}
		}
		else 
		{
			LOG((1,"License: Error in AcquireContext 0x%08x",GetLastError()));
			if (buff) DrvFree(buff);
			return 7;
		}
	}

	// Use the CryptImportKey function to import the PLAINTEXTKEYBLOB
	// BYTE array into the key container. The function returns a 
	// pointer to an HCRYPTKEY variable that contains the handle of
	// the imported key.

	if (!CryptImportKey(
		hProv,
		DesKeyBlob,
		sizeof(DesKeyBlob),
		0,
		CRYPT_EXPORTABLE,
		&hKey ) )
	{
		LOG((1,"License: Error 0x%08x in importing the Des key",GetLastError()));
		if (buff) DrvFree(buff);
		if (hProv) CryptReleaseContext(hProv, 0);
		return 7;
	}

	if (!CryptDecrypt(
		hKey,			  //__in     HCRYPTKEY hKey,
		0,				  //__in     HCRYPTHASH hHash,
		TRUE,			  //__in     BOOL Final,
		0,				  //__in     DWORD dwFlags,
		(BYTE *) buff,	  //__inout  BYTE *pbData,
		&bufflen		  //__inout  DWORD *pdwDataLen
		) )
	{
		LOG((1,"License: Error 0x%08x during decryption",GetLastError()));
		if (buff) DrvFree(buff);
		if (hProv) CryptReleaseContext(hProv, 0);
		return 8;
	}
	if (hProv) CryptReleaseContext(hProv, 0);

	// zero terminate the decrypted license (make it a string)
	// not needed as the encrypted string contains \0
	//*(buff+bufflen) = '\0';
	
	// parse the decoded license string
	LOG((1,"License: parsing license string: %s", buff));
	buffbackup = buff;

	// License Identifier
	gLicense.licenseIdentifier = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license identifier %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	buff = next + 1;

	// verify license identifier
	if ( StrCmp(gLicense.licenseIdentifier, gszHttpTapiLicenseIdentifier) ) {
		LOG((1,"License: wrong license identifier. %s!=%s", gLicense.licenseIdentifier, gszHttpTapiLicenseIdentifier));
		if (buffbackup) DrvFree(buffbackup);
		return 3;
	}

	// License Version
	gLicense.licenseVersion = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license version %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	gLicense.iLicenseVersion = StrToInt(gLicense.licenseVersion);
	buff = next + 1;

	// verify license version
	if (gLicense.iLicenseVersion != gszHttpTapiLicenseVersion) {
		LOG((1,"License: wrong license version. %d!=%d", gLicense.iLicenseVersion, gszHttpTapiLicenseVersion));
		if (buffbackup) DrvFree(buffbackup);
		return 4;
	}

	// Name
	gLicense.name = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license name %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	buff = next + 1;

	// Company
	gLicense.company = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license company %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	buff = next + 1;	

	// Address
	gLicense.address = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license address %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	buff = next + 1;	

	// Valid until
	gLicense.validUntil = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license validity %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	buff = next + 1;


	// Number of lines
	gLicense.numberOfLines = buff;
	if ( (next=StrChr(buff,'\n')) == 0 ) {
		LOG((1,"License: error parsing license number of lines %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}
	*next = '\0';
	gLicense.iNumberOfLines = StrToInt(gLicense.numberOfLines);
	buff = next + 1;	

	// additional data
	gLicense.additionalData = buff;
	if ( (next=StrChr(buff,'\n')) != 0 ) {
		LOG((1,"License: error parsing additional data %s", buff));
		if (buffbackup) DrvFree(buffbackup);
		return 2;
	}

	// decryption was successfull
	LOG((3,"License: successfully decrypted license!"));
	LOG((3,"License:   License Identifier: %s",gLicense.licenseIdentifier));
	LOG((3,"License:   License Version:    %d",gLicense.iLicenseVersion));
	LOG((3,"License:   Name:               %s",gLicense.name));
	LOG((3,"License:   Company:            %s",gLicense.company));
	LOG((3,"License:   Address:            %s",gLicense.address));
	LOG((3,"License:   Valid Until:        %s",gLicense.validUntil));
	LOG((3,"License:   Number of Lines:    %d",gLicense.iNumberOfLines));
	LOG((3,"License:   Additional Data:    %s",gLicense.additionalData));
	LOG((3,"License: ----------------------"));

	if (gLicenseString) {
		LOG((5,"freeing existing licenseString %p",gLicenseString));
		DrvFree(gLicenseString);
	}
	gLicenseString = buffbackup;

	return 0;
};

void set_gdwNumberOfLines(int dialog) {
	// verify the license (load number of licensed lines)
	HKEY    hKey;
	DWORD   dwDataSize, dwDataType, ret;
	char    szencryptedLicense[MAX_LICENSE_LENGTH];

#ifdef SINGLELINE
	gdwNumberOfLines = 1;
	return;
#endif
#ifdef NOLICENSE
	gdwNumberOfLines = 9999;
	return;
#endif

	//DebugBreak();

	RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		gszHttpTapiKeyFull,
		0,
		KEY_ALL_ACCESS,
		&hKey
		);

	dwDataSize = MAX_LICENSE_LENGTH;
	if (RegQueryValueEx(
		hKey,
		gszHttpTapiLicense,
		0,
		&dwDataType,
		(LPBYTE) szencryptedLicense,
		&dwDataSize
		)) {
			// error, no license found
			LOG((1,"License: failed reading license ..."));
			if (dialog) MessageBox(0, 
				"Could not found a license - please configure a valid license!", 
				"HttpTapi", 
				MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
			gdwNumberOfLines = 0;
	} else {
		LOG((3,"License: decrypting license ..."));
		ret = decryptLicense(&gLicense, szencryptedLicense);
		LOG((3,"License: decrypting license ... done"));
		if (ret) {
			// error decrypting license
			LOG((3,"License: invalid license ..."));
			if (dialog) MessageBox(0, 
				"License is invalid - please configure a valid license!", 
				"HttpTapi", 
				MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
			gdwNumberOfLines = 0;
		} else if (strlen(gLicense.validUntil) == 0) {
			// no validity date -> license does not expire
			LOG((3,"License: license does not expire ..."));
			gdwNumberOfLines = gLicense.iNumberOfLines;
		} else {
			// verify if license is still valid
			SYSTEMTIME currentSystemTime, licenseSystemTime;
			LOG((3,"License: verify if license is still valid ..."));
			GetLocalTime(&currentSystemTime);
			GetLocalTime(&licenseSystemTime); // workaround to init the structure :-)
			LOG((3,"License: parsing validity date ..."));
			if (sscanf_s(gLicense.validUntil, 
				"%04u-%02u-%02u", &licenseSystemTime.wYear, 
				&licenseSystemTime.wMonth, &licenseSystemTime.wDay) != 3) {
					// error parsing date
					LOG((3,"License: invalid license date ..."));
					if (dialog) MessageBox(0, "Wrong license validity - please configure a valid license!", 
						"HttpTapi", MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
					gdwNumberOfLines = 0;
			} else {
				// compare timestamps
				FILETIME currentFileTime, licenseFileTime;
				LOG((3,"License: compare expiration date ..."));
				SystemTimeToFileTime(&currentSystemTime, &currentFileTime);
				SystemTimeToFileTime(&licenseSystemTime, &licenseFileTime);
				if (CompareFileTime(&currentFileTime,&licenseFileTime) == 1) {
					// license expired
					LOG((3,"License: licensed expired at %s",gLicense.validUntil));
					if (dialog) MessageBox(0, "License expired - please configure a valid license!", 
						"HttpTapi", MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
					gdwNumberOfLines = 0;
				} else {
					// license valid
					LOG((3,"License: licensed still valid (till %s (%04u-%02u-%02u))",gLicense.validUntil,
						licenseSystemTime.wYear, licenseSystemTime.wMonth, licenseSystemTime.wDay));
					gdwNumberOfLines = gLicense.iNumberOfLines;
				}
			}

		}
	}

	RegCloseKey (hKey);
}

BOOL
WINAPI
DllMain(
    HANDLE  hDLL,
    DWORD   dwReason,
    LPVOID  lpReserved
    )
{
#ifdef LOGGING
	{
		HKEY    hKey;
		DWORD   dwDataSize, dwDataType, dwDebugLevel=0;


		RegOpenKeyExA(
			HKEY_LOCAL_MACHINE,
			gszHttpTapiKeyFull,
			0,
			KEY_ALL_ACCESS,
			&hKey
			);

		dwDataSize = sizeof (DWORD);

		RegQueryValueEx(
			hKey,
			gszHttpTapiDebugLevel,
			0,
			&dwDataType,
			(LPBYTE) &dwDebugLevel,
			&dwDataSize
			);

		LOG((3,"DllMain: setting debug level to %d", dwDebugLevel));
		setLogLevel(dwDebugLevel);

		RegCloseKey (hKey);
	}
#endif

	if (dwReason ==  DLL_PROCESS_ATTACH)
	{
		ghInst = hDLL;
		gLicenseString = NULL;
		gdwNumberOfLines = 0;
		gpfnLineCreateProc = NULL;
		LOG((5,"DllMain: entering with DLL_PROCESS_ATTACH ..."));
	} else if (dwReason ==  DLL_PROCESS_DETACH) {
		LOG((5,"DllMain: entering with DLL_PROCESS_DETACH ..."));
	} else if (dwReason ==  DLL_THREAD_ATTACH) {
		LOG((5,"DllMain: entering with DLL_THREAD_ATTACH ..."));
	} else if (dwReason ==  DLL_THREAD_DETACH) {
		LOG((5,"DllMain: entering with DLL_THREAD_DETACH ..."));
	}

	return TRUE;
}

//
// We get a slough of C4047 (different levels of indrection) warnings down
// below in the initialization of FUNC_PARAM structs as a result of the
// real func prototypes having params that are types other than DWORDs,
// so since these are known non-interesting warnings just turn them off
//

#pragma warning (disable:4047)


//
// --------------------------- TAPI_lineXxx funcs -----------------------------
//

LONG
TSPIAPI
TSPI_lineClose(
    HDRVLINE    hdLine
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine, hdLine }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineClose",
        1,
        params,
    };
#endif

    Prolog (&info);
    DrvFree ((PDRVLINE) hdLine);
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineCloseCall(
    HDRVCALL    hdCall
    )
{
    PDRVLINE    pLine = (PDRVLINE) hdCall;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdCall, hdCall  }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineCloseCall",
        1,
        params
    };
#endif


    //
    // Note that in TAPI 2.0 TSPI_lineCloseCall can get called
    // without TSPI_lineDrop ever being called, so we need to
    // be prepared for either case.
    //

    Prolog (&info);
    DropActiveCall (pLine);
    pLine->htCall = NULL;
    return (Epilog (&info, 0));
}


LONG
TSPIAPI
TSPI_lineConditionalMediaDetection(
    HDRVLINE            hdLine,
    DWORD               dwMediaModes,
    LPLINECALLPARAMS    const lpCallParams
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,        hdLine       },
        { "dwMediaModes",   dwMediaModes },
        { gszlpCallParams,  lpCallParams }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineConditionalMediaDetection",
        3,
        params
    };
#endif


    //
    // This func is really a no-op for us, since we don't look
    // for incoming calls (though we do say we support them to
    // make apps happy)
    //

    Prolog (&info);
    return (Epilog (&info, 0));
}


LONG
TSPIAPI
TSPI_lineDrop(
    DRV_REQUESTID   dwRequestID,
    HDRVCALL        hdCall,
    LPCSTR          lpsUserUserInfo,
    DWORD           dwSize
    )
{
    PDRVLINE    pLine = (PDRVLINE) hdCall;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwRequestID,        dwRequestID     },
        { gszhdCall,             hdCall          },
        { "lpsUserUserInfo",    lpsUserUserInfo },
        { gszdwSize,             dwSize          }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineDrop",
        4,
        params
    };
#endif

    Prolog (&info);
    DropActiveCall (pLine);
    SetCallState (pLine, LINECALLSTATE_IDLE, 0);

	/* Klaus: ConnectWise CRM does lineMakeCall, TSPI_lineDrop, lineMakeCall, TSPI_lineDrop ... without TSPI_lineCloseCall.
	 * Therefore I reset pLine->htCall already during TSPI_lineDrop (and not only during TSPI_lineCloseCall) to allow subsequent
	 * lineMakeCall.
	*/
	pLine->htCall = NULL;

    (*gpfnCompletionProc)(dwRequestID, 0);
    return (Epilog (&info, dwRequestID));
}


LONG
TSPIAPI
TSPI_lineGetAddressCaps(
    DWORD              dwDeviceID,
    DWORD              dwAddressID,
    DWORD              dwTSPIVersion,
    DWORD              dwExtVersion,
    LPLINEADDRESSCAPS  lpAddressCaps
    )
{

#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwDeviceID,     dwDeviceID      },
        { "dwAddressID",    dwAddressID     },
        { "dwTSPIVersion",  dwTSPIVersion   },
        { "dwExtVersion",   dwExtVersion    },
        { "lpAddressCaps",  lpAddressCaps   }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetAddressCaps",
        5,
        params
    };
#endif

    LONG        lResult = 0;


    Prolog (&info);

    if (dwAddressID != 0)
    {
        lResult = LINEERR_INVALADDRESSID;
    }

    lpAddressCaps->dwNeededSize =
    lpAddressCaps->dwUsedSize   = sizeof(LINEADDRESSCAPS);

    lpAddressCaps->dwLineDeviceID       = dwDeviceID;
    lpAddressCaps->dwAddressSharing     = LINEADDRESSSHARING_PRIVATE;
    lpAddressCaps->dwCallInfoStates     = LINECALLINFOSTATE_MEDIAMODE |
                                          LINECALLINFOSTATE_APPSPECIFIC;
    lpAddressCaps->dwCallerIDFlags      =
    lpAddressCaps->dwCalledIDFlags      =
    lpAddressCaps->dwRedirectionIDFlags =
    lpAddressCaps->dwRedirectingIDFlags = LINECALLPARTYID_UNAVAIL;
    lpAddressCaps->dwCallStates         = LINECALLSTATE_IDLE |
                                          LINECALLSTATE_OFFERING |
                                          LINECALLSTATE_ACCEPTED |
                                          LINECALLSTATE_DIALTONE |
                                          LINECALLSTATE_DIALING |
                                          LINECALLSTATE_CONNECTED |
                                          LINECALLSTATE_PROCEEDING |
                                          LINECALLSTATE_DISCONNECTED |
                                          LINECALLSTATE_UNKNOWN;
    lpAddressCaps->dwDialToneModes      = LINEDIALTONEMODE_UNAVAIL;
    lpAddressCaps->dwBusyModes          = LINEBUSYMODE_UNAVAIL;
    lpAddressCaps->dwSpecialInfo        = LINESPECIALINFO_UNAVAIL;
    lpAddressCaps->dwDisconnectModes    = LINEDISCONNECTMODE_NORMAL |
                                          LINEDISCONNECTMODE_BUSY |
                                          LINEDISCONNECTMODE_NOANSWER |
                                          LINEDISCONNECTMODE_UNAVAIL |
                                          LINEDISCONNECTMODE_NODIALTONE;
    lpAddressCaps->dwMaxNumActiveCalls  = 1;
    lpAddressCaps->dwAddrCapFlags       = LINEADDRCAPFLAGS_DIALED;
    lpAddressCaps->dwCallFeatures       = LINECALLFEATURE_ACCEPT |
                                          LINECALLFEATURE_ANSWER |
                                          LINECALLFEATURE_DROP |
                                          LINECALLFEATURE_SETCALLPARAMS;
    lpAddressCaps->dwAddressFeatures    = LINEADDRFEATURE_MAKECALL;

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineGetAddressStatus(
    HDRVLINE            hdLine,
    DWORD               dwAddressID,
    LPLINEADDRESSSTATUS lpAddressStatus
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,             hdLine         },
        { "dwAddressID",        dwAddressID     },
        { "lpAddressStatus",    lpAddressStatus }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetAddressStatus",
        3,
        params
    };
#endif

    LONG        lResult = 0;
    PDRVLINE    pLine = (PDRVLINE) hdLine;


    Prolog (&info);

    lpAddressStatus->dwNeededSize =
    lpAddressStatus->dwUsedSize   = sizeof(LINEADDRESSSTATUS);

    lpAddressStatus->dwNumActiveCalls  = (pLine->htCall ? 1 : 0);
    lpAddressStatus->dwAddressFeatures = LINEADDRFEATURE_MAKECALL;

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineGetCallAddressID(
    HDRVCALL            hdCall,
    LPDWORD             lpdwAddressID
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdCall,        hdCall          },
        { "lpdwAddressID",  lpdwAddressID   }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetCallAddressID",
        2,
        params
    };
#endif


    //
    // We only support 1 address (id=0)
    //

    Prolog (&info);
    *lpdwAddressID = 0;
    return (Epilog (&info, 0));
}


LONG
TSPIAPI
TSPI_lineGetCallInfo(
    HDRVCALL        hdCall,
    LPLINECALLINFO  lpLineInfo
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdCall,     hdCall      },
        { "lpLineInfo", lpLineInfo  }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetCallInfo",
        2,
        params
    };
#endif
    LONG        lResult = 0;
    PDRVLINE    pLine = (PDRVLINE) hdCall;


    Prolog (&info);

    lpLineInfo->dwNeededSize =
    lpLineInfo->dwUsedSize   = sizeof(LINECALLINFO);

    lpLineInfo->dwBearerMode         = LINEBEARERMODE_VOICE;
    lpLineInfo->dwMediaMode          = pLine->dwMediaMode;
    lpLineInfo->dwCallStates         = LINECALLSTATE_IDLE |
                                       LINECALLSTATE_DIALTONE |
                                       LINECALLSTATE_DIALING |
                                       LINECALLSTATE_CONNECTED |
                                       LINECALLSTATE_PROCEEDING |
                                       LINECALLSTATE_DISCONNECTED |
                                       LINECALLSTATE_UNKNOWN;
    lpLineInfo->dwOrigin             = LINECALLORIGIN_OUTBOUND;
    lpLineInfo->dwReason             = LINECALLREASON_DIRECT;
    lpLineInfo->dwCallerIDFlags      =
    lpLineInfo->dwCalledIDFlags      =
    lpLineInfo->dwConnectedIDFlags   =
    lpLineInfo->dwRedirectionIDFlags =
    lpLineInfo->dwRedirectingIDFlags = LINECALLPARTYID_UNAVAIL;

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineGetCallStatus(
    HDRVCALL            hdCall,
    LPLINECALLSTATUS    lpLineStatus
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdCall,         hdCall          },
        { "lpLineStatus",   lpLineStatus    }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetCallStatus",
        2,
        params
    };
#endif
    LONG        lResult = 0;
    PDRVLINE    pLine = (PDRVLINE) hdCall;


    Prolog (&info);

    lpLineStatus->dwNeededSize =
    lpLineStatus->dwUsedSize   = sizeof(LINECALLSTATUS);

    lpLineStatus->dwCallState  = pLine->dwCallState;

    if (pLine->dwCallState != LINECALLSTATE_IDLE)
    {
        lpLineStatus->dwCallFeatures = LINECALLFEATURE_DROP;
    }

    return (Epilog (&info, lResult));
}

LONG TSPIAPI TSPI_providerCreateLineDevice(
    DWORD_PTR 	dwTempID,
    DWORD 		dwDeviceID
	)
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "dwTempID",    dwTempID    },
        { "dwDeviceID",  dwDeviceID  }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerCreateLineDevice",
        2,
        params
    };
#endif

    LONG            lResult = 0;

	Prolog (&info);
	
    return (Epilog (&info, lResult));
};


LONG
TSPIAPI
TSPI_lineGetDevCaps(
    DWORD           dwDeviceID,
    DWORD           dwTSPIVersion,
    DWORD           dwExtVersion,
    LPLINEDEVCAPS   lpLineDevCaps
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwDeviceID,    dwDeviceID      },
        { "dwTSPIVersion",  dwTSPIVersion   },
        { "dwExtVersion",   dwExtVersion    },
        { "lpLineDevCaps",  lpLineDevCaps   }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetDevCaps",
        4,
        params
    };
#endif

    LONG            lResult = 0;
    static WCHAR    szProviderInfo[] = L"Generic HTTP TAPI service provider";

    #define PROVIDER_INFO_SIZE (35 * sizeof (WCHAR))

    Prolog (&info);

    lpLineDevCaps->dwNeededSize = sizeof (LINEDEVCAPS) + PROVIDER_INFO_SIZE +
        (MAX_REGKEYVAL_LENGTH + 1) * sizeof (WCHAR);

    if (lpLineDevCaps->dwTotalSize >= lpLineDevCaps->dwNeededSize)
    {
        #define LINECONFIG_SIZE   (2 * (MAX_REGKEYVAL_LENGTH + 1) + 40)

        char    szLineConfig[MAX_REGKEYVAL_LENGTH], szLineN[MAX_REGKEYNAME_LENGTH], szLineName[MAX_REGKEYVAL_LENGTH];
        HKEY    hKey;
        DWORD   dwDataSize, dwDataType;


        lpLineDevCaps->dwUsedSize = lpLineDevCaps->dwNeededSize;

        lpLineDevCaps->dwProviderInfoSize   = PROVIDER_INFO_SIZE;
        lpLineDevCaps->dwProviderInfoOffset = sizeof(LINEDEVCAPS);

        My_lstrcpyW ((WCHAR *)(lpLineDevCaps + 1), szProviderInfo);

        RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            gszHttpTapiKeyFull,
            0,
            KEY_ALL_ACCESS,
            &hKey
            );

        dwDataSize = LINECONFIG_SIZE;
        wsprintf (szLineN, "Line%dName", dwDeviceID - gdwLineDeviceIDBase);
        strncpy (szLineConfig, gszHttpTapiDefLineConfigParamsName, MAX_REGKEYVAL_LENGTH-1);
		szLineConfig[MAX_REGKEYVAL_LENGTH-1] = '\0';

        RegQueryValueEx(
            hKey,
            szLineN,
            0,
            &dwDataType,
            (LPBYTE) szLineConfig,
            &dwDataSize
            );

        RegCloseKey (hKey);

		_snprintf(szLineName, MAX_REGKEYVAL_LENGTH-1, "HTTPTAPI %02d: %s", dwDeviceID-gdwLineDeviceIDBase+1, szLineConfig);
		szLineName[sizeof(szLineName)-1] = 0;

		lpLineDevCaps->dwLineNameSize   = (lstrlen (szLineName) + 1) *
            sizeof (WCHAR);
        lpLineDevCaps->dwLineNameOffset = sizeof(LINEDEVCAPS) +
            PROVIDER_INFO_SIZE;

        MultiByteToWideChar(
            CP_ACP,
            MB_PRECOMPOSED,
            szLineName,
            -1,
            (WCHAR *) ((LPBYTE) (lpLineDevCaps + 1) + PROVIDER_INFO_SIZE),
            (lpLineDevCaps->dwLineNameSize)/sizeof(WCHAR)
            );
    }
    else
    {
        lpLineDevCaps->dwUsedSize = sizeof(LINEDEVCAPS);
    }

    lpLineDevCaps->dwStringFormat      = STRINGFORMAT_ASCII;

	// assign a permanent line ID (from "Windows telephony programming: a developer's guide to TAPI" by Chris Sells)
	// this enables dialer.exe to "remember" the choosen line for the next call, but may cause confusion when
	// lines are added/removed, as the order of the lines may change
	// ToDo: store the permanent ID also in registry to keep it constant when adding/deleting lines
//#define MAKEPERMLINEID(dwPermProviderID, dwDeviceID) ((LOWORD(dwPermProviderID) << 16) | dwDeviceID)
	// KlausDarilion: when the TSP is used on multiple terminal servers the PermantLineId should be the
	// same on all of them.
#define MAKEPERMLINEID(dwPermProviderID, dwDeviceID) ((LOWORD(1975) << 16) | dwDeviceID)

	lpLineDevCaps->dwPermanentLineID   = MAKEPERMLINEID(gdwPermanentProviderID, dwDeviceID - gdwLineDeviceIDBase);

	lpLineDevCaps->dwAddressModes      = LINEADDRESSMODE_ADDRESSID;
    lpLineDevCaps->dwNumAddresses      = 1;
    lpLineDevCaps->dwBearerModes       = LINEBEARERMODE_VOICE;
    lpLineDevCaps->dwMediaModes        = LINEMEDIAMODE_INTERACTIVEVOICE;


    lpLineDevCaps->dwDevCapFlags       = LINEDEVCAPFLAGS_CLOSEDROP;

	lpLineDevCaps->dwAddressTypes	   =  LINEADDRESSTYPE_PHONENUMBER;

    lpLineDevCaps->dwMaxNumActiveCalls = 1;
    lpLineDevCaps->dwRingModes         = 1;
    lpLineDevCaps->dwLineFeatures      = LINEFEATURE_MAKECALL;

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineGetID(
    HDRVLINE    hdLine,
    DWORD       dwAddressID,
    HDRVCALL    hdCall,
    DWORD       dwSelect,
    LPVARSTRING lpDeviceID,
    LPCWSTR     lpszDeviceClass,
    HANDLE      hTargetProcess
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,             hdLine          },
        { "dwAddressID",        dwAddressID     },
        { gszhdCall,             hdCall          },
        { "dwSelect",           dwSelect        },
        { "lpDeviceID",         lpDeviceID      },
        { "lpszDeviceClass",    lpszDeviceClass },
        { "hTargetProcess",     hTargetProcess  }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetID",
        7,
        params
    };
#endif

    DWORD       dwNeededSize = sizeof(VARSTRING) + sizeof (DWORD);
    LONG        lResult = 0;
    PDRVLINE    pLine = (dwSelect == LINECALLSELECT_CALL ?
                    (PDRVLINE) hdCall : (PDRVLINE) hdLine);


    Prolog (&info);

    if (lstrcmpiW (lpszDeviceClass, L"tapi/line") == 0)
    {
        if (lpDeviceID->dwTotalSize < dwNeededSize)
        {
            lpDeviceID->dwUsedSize = 3*sizeof(DWORD);
        }
        else
        {
            lpDeviceID->dwUsedSize = dwNeededSize;

            lpDeviceID->dwStringFormat = STRINGFORMAT_BINARY;
            lpDeviceID->dwStringSize   = sizeof(DWORD);
            lpDeviceID->dwStringOffset = sizeof(VARSTRING);

            *((LPDWORD)(lpDeviceID + 1)) = pLine->dwDeviceID;
        }

        lpDeviceID->dwNeededSize = dwNeededSize;
    }
    else if (lstrcmpiW (lpszDeviceClass, L"comm/datamodem") == 0)
    {
#ifdef _WIN64
        dwNeededSize += ((DWORD)strlen(pLine->szComm) + 1) * sizeof (WCHAR);
#else
        dwNeededSize += (strlen (pLine->szComm) + 1) * sizeof (WCHAR);
#endif

        if (lpDeviceID->dwTotalSize < dwNeededSize)
        {
            lpDeviceID->dwUsedSize = 3 * sizeof(DWORD);
        }
        else
        {
            HANDLE hCommDup = NULL;


            if (!pLine->htCall)
            {
                LOG((1, "TSPI_lineGetID32: error, no active call"));

                lResult = LINEERR_OPERATIONFAILED;

                goto TSPI_lineGetID_epilog;
            }

            if (!DuplicateHandle(
                    GetCurrentProcess(),
                    pLine->hComm,
                    hTargetProcess,
                    &hCommDup,
                    0,
                    TRUE,
                    DUPLICATE_SAME_ACCESS
                    ))
            {
                LOG((
                    1,
                    "TSPI_lineGetID: DupHandle failed, err=%ld",
                    GetLastError()
                    ));

                lResult = LINEERR_OPERATIONFAILED;

                goto TSPI_lineGetID_epilog;
            }

            lpDeviceID->dwUsedSize = dwNeededSize;

            lpDeviceID->dwStringFormat = STRINGFORMAT_BINARY;
            lpDeviceID->dwStringSize   = dwNeededSize - sizeof(VARSTRING);
            lpDeviceID->dwStringOffset = sizeof(VARSTRING);

            *((HANDLE *)(lpDeviceID + 1)) = hCommDup;

            strncpy(
                ((char *)(lpDeviceID + 1)) + sizeof (HANDLE),
                pLine->szComm,
				lpDeviceID->dwTotalSize - sizeof(VARSTRING) -sizeof(HANDLE)
                );
				*(char * ) (lpDeviceID + lpDeviceID->dwTotalSize-1) = '\0';

            MultiByteToWideChar(
                CP_ACP,
                0,
                pLine->szComm,
                -1,
                ((WCHAR *)(lpDeviceID + 1)) + sizeof (HANDLE),
                (lpDeviceID->dwTotalSize - sizeof(VARSTRING) -sizeof(HANDLE))/sizeof(WCHAR)
                );
        }

        lpDeviceID->dwNeededSize = dwNeededSize;
    }
    else
    {
        lResult = LINEERR_NODEVICE;
    }

TSPI_lineGetID_epilog:

    return (Epilog (&info, lResult));
}

// implemented to debug the issue, that dialer.exe does not accept the line.
// not needed ...
LONG
TSPIAPI
TSPI_lineGetExtensionID(
	DWORD dwDeviceID,
	DWORD dwTSPIVersion,
	LPLINEEXTENSIONID lpExtensionID
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "dwDeviceID",    dwDeviceID   },
        { "dwTSPIVersion", dwTSPIVersion},
        { "lpExtensionID", lpExtensionID}
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetExtensionID",
        3,
        params
    };
#endif

	Prolog (&info);

	lpExtensionID->dwExtensionID0 = 0;
	lpExtensionID->dwExtensionID1 = 0;
	lpExtensionID->dwExtensionID2 = 0;
	lpExtensionID->dwExtensionID3 = 0;

    return (Epilog (&info, 0));
}

LONG
TSPIAPI
TSPI_lineGetLineDevStatus(
    HDRVLINE        hdLine,
    LPLINEDEVSTATUS lpLineDevStatus
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,            hdLine          },
        { "lpLineDevStatus",    lpLineDevStatus }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetLineDevStatus",
        2,
        params
    };
#endif

    LONG        lResult = 0;
    PDRVLINE    pLine = (PDRVLINE) hdLine;


    Prolog (&info);

    lpLineDevStatus->dwUsedSize =
    lpLineDevStatus->dwNeededSize = sizeof (LINEDEVSTATUS);

    lpLineDevStatus->dwNumActiveCalls = (pLine->htCall ? 1 : 0);
    //lpLineDevStatus->dwLineFeatures =
    lpLineDevStatus->dwDevStatusFlags = LINEDEVSTATUSFLAGS_CONNECTED |
                                        LINEDEVSTATUSFLAGS_INSERVICE;
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineGetNumAddressIDs(
    HDRVLINE    hdLine,
    LPDWORD     lpdwNumAddressIDs
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,            hdLine            },
        { "lpdwNumAddressIDs",  lpdwNumAddressIDs }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineGetNumAddressIDs",
        2,
        params
    };
#endif

    LONG        lResult = 0;
    PDRVLINE    pLine = (PDRVLINE) hdLine;


    //
    // We only support 1 address (id=0)
    //

    Prolog (&info);
    *lpdwNumAddressIDs = 1;
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineSetStatusMessages(
    HDRVLINE hdLine,
    DWORD dwLineStates,
    DWORD dwAddressStates
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,            hdLine            },
        { "dwLineStates",  dwLineStates },
        { "dwAddressStates",  dwAddressStates }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineSetStatusMessages",
        3,
        params
    };
#endif

    LONG        lResult = 0;
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineMakeCall(
    DRV_REQUESTID       dwRequestID,
    HDRVLINE            hdLine,
    HTAPICALL           htCall,
    LPHDRVCALL          lphdCall,
    LPCWSTR             lpszDestAddress,
    DWORD               dwCountryCode,
    LPLINECALLPARAMS    const lpCallParams
    )
{
    char        szDestAddress[128], szParsedNumber[128];
	char		szConfigUri[MAX_REGKEYVAL_LENGTH], szConfigCa[MAX_REGKEYVAL_LENGTH];
    PDRVLINE    pLine = (PDRVLINE) hdLine;
	int iUseWindowsCertStore;
	long responseCode = 0; //identical to HTTP timeout

#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwRequestID,       dwRequestID     },
        { gszhdLine,            hdLine          },
        { "htCall",             htCall          },
        { "lphdCall",           lphdCall        },
//        { "lpszDestAddress",    szDestAddress   },
        { "dwCountryCode",      dwCountryCode   },
        { gszlpCallParams,      lpCallParams    }
    };
    FUNC_INFO info =
    {
        "TSPI_lineMakeCall",
//        7,
        6,
        params
    };
#endif
    Prolog (&info);

    if (lpszDestAddress)
    {
		size_t i=0, j=0;

		WideCharToMultiByte(
            CP_ACP,
            0,
            lpszDestAddress,
            -1,
            (LPSTR) szDestAddress,
            128,
            NULL,
            NULL
            );
		LOG((3,"TSPI_lineMakeCall: called phone number: %s, removing bad digits ...", szDestAddress));
 
		// remove bad characters from dialstring
		for(i=0; i<strlen(szDestAddress); i++) {
			if ( ((szDestAddress[i] >= '0') && (szDestAddress[i] <= '9')) 
				|| (szDestAddress[i] == '+') || (szDestAddress[i] == '*')
				|| (szDestAddress[i] == '#') ) {
					szParsedNumber[j] = szDestAddress[i];
					j++;
				}
		}
		szParsedNumber[j] = '\0';
		LOG((3,"TSPI_lineMakeCall: parsed phone number: %s", szParsedNumber));
    }

    //
    // Check to see if there's already another call
    //

    if (pLine->htCall)
    {
		LOG((1,"TSPI_lineMakeCall: LINEERR_CALLUNAVAIL"));
        (*gpfnCompletionProc)(dwRequestID, LINEERR_CALLUNAVAIL);
        goto TSPI_lineMakeCall_return;
    }


    //
    // Since we don't support TSPI_lineDial, fail if app tries
    // to pass a NULL lpszDestAddress (implying that app just
    // wants to go offhook)
    //

    if (lpszDestAddress == NULL) {
		LOG((1,"TSPI_lineMakeCall: LINEERR_INVALADDRESS"));
        (*gpfnCompletionProc)(dwRequestID, LINEERR_INVALADDRESS);
        goto TSPI_lineMakeCall_return;
    }

	// check the number of licensed lines
	if ( (((PDRVLINE) hdLine)->dwDeviceID - gdwLineDeviceIDBase) > (gdwNumberOfLines - 1) ) {
		LOG((1,"TSPI_lineMakeCall: LINEERR_RESOURCEUNAVAIL"));
        (*gpfnCompletionProc)(dwRequestID, LINEERR_RESOURCEUNAVAIL);
        goto TSPI_lineMakeCall_return;
    }

    //
    // Get the line's config info
    //

    {
        HKEY    hKey;
        DWORD   dwDataSize, dwDataType;
        char    szLineN[MAX_REGKEYNAME_LENGTH];
		LONG lResult;

        lResult = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            gszHttpTapiKeyFull,
            0,
            KEY_ALL_ACCESS,
            &hKey
            );
		if (0 != lResult) {
			LOG((1,"TSPI_lineMakeCall: error opening registry -> LINEERR_RESOURCEUNAVAIL"));
		    (*gpfnCompletionProc)(dwRequestID, LINEERR_RESOURCEUNAVAIL);
			goto TSPI_lineMakeCall_return;
		}

		// fetch Line Config: (we only fetch the URI(s) and SSL config)
		dwDataSize = MAX_REGKEYVAL_LENGTH;
        wsprintf(szLineN, "Line%dUri", ((PDRVLINE) hdLine)->dwDeviceID - gdwLineDeviceIDBase);
		LOG((3,"TSPI_lineMakeCall: Reading %s key ...", szLineN));
        lResult=RegQueryValueEx(
            hKey,
            szLineN,
            0,
            &dwDataType,
            (LPBYTE) szConfigUri,
            &dwDataSize
            );
		if (0 != lResult) {
			RegCloseKey (hKey);
			LOG((1,"TSPI_lineMakeCall: error reading key %s -> LINEERR_RESOURCEUNAVAIL", szLineN));
		    (*gpfnCompletionProc)(dwRequestID, LINEERR_RESOURCEUNAVAIL);
			goto TSPI_lineMakeCall_return;
		}
		LOG((3,"TSPI_lineMakeCall: Fetched line config from Registry: Uri=%s", szConfigUri));

		dwDataSize = MAX_REGKEYVAL_LENGTH;
        wsprintf(szLineN, "Line%dCa", ((PDRVLINE) hdLine)->dwDeviceID - gdwLineDeviceIDBase);
		LOG((3,"TSPI_lineMakeCall: Reading %s key ...", szLineN));
        lResult = RegQueryValueEx(
            hKey,
            szLineN,
            0,
            &dwDataType,
            (LPBYTE) szConfigCa,
            &dwDataSize
            );
		if (0 != lResult) {
			RegCloseKey (hKey);
			LOG((1,"TSPI_lineMakeCall: error reading key %s -> LINEERR_RESOURCEUNAVAIL", szLineN));
		    (*gpfnCompletionProc)(dwRequestID, LINEERR_RESOURCEUNAVAIL);
			goto TSPI_lineMakeCall_return;
		}
		LOG((3,"TSPI_lineMakeCall: Fetched line config from Registry: CA=%s", szConfigCa));

		dwDataSize = sizeof(iUseWindowsCertStore);
		iUseWindowsCertStore = 0;
		RegQueryValueEx(
			hKey,
			gszHttpTapiCertStore,
			0,
			&dwDataType,
			(LPBYTE) &iUseWindowsCertStore,
			&dwDataSize
			);
		LOG((3,"TSPI_lineMakeCall: %s=%d",gszHttpTapiCertStore,iUseWindowsCertStore));

		RegCloseKey (hKey);

	}


    //
    // Init the data structure & tell tapi our handle to the call
    //
	LOG((3,"TSPI_lineMakeCall: Init the data structure & tell tapi our handle to the call"));
	pLine->htCall          = htCall;
    pLine->bDropInProgress = FALSE;
    pLine->dwMediaMode     = (lpCallParams ? lpCallParams->dwMediaMode :
        LINEMEDIAMODE_INTERACTIVEVOICE);

    *lphdCall = (HDRVCALL) pLine;

	//
	// Perform HTTP request using libcurl
	//
	{
		char szFinalUri[MAX_REGKEYVAL_LENGTH];
		char *p, *szCurrentUri, *szNextUri;
		CURL *easyhandle;
		char *escaped_number=0;
		CURLcode ret;

		LOG((3,"TSPI_lineMakeCall: Perform HTTP request using libcurl"));
		LOG((3,"TSPI_lineMakeCall: initialize curl ..."));
		easyhandle = curl_easy_init(); 
		if (easyhandle) {
			LOG((3,"TSPI_lineMakeCall: curl_easy_init succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_TIMEOUT, 3);
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_TIMEOUT failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_TIMEOUT succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_CONNECTTIMEOUT, 3);
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_CONNECTTIMEOUT failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_CONNECTTIMEOUT succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_USERAGENT, "HttpTapi");
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_USERAGENT failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_USERAGENT succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_COOKIEFILE, "");
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_COOKIEFILE failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_COOKIEFILE succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_FOLLOWLOCATION, 1L);
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_FOLLOWLOCATION failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_FOLLOWLOCATION succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_MAXREDIRS, 20L);
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_MAXREDIRS failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_MAXREDIRS succeeded"));

			ret = curl_easy_setopt(easyhandle, CURLOPT_HTTPAUTH, CURLAUTH_BASIC|CURLAUTH_DIGEST);
			if (ret != CURLE_OK) {
				LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_HTTPAUTH failed: %s",curl_easy_strerror(ret)));
				curl_easy_cleanup(easyhandle);
				pLine->htCall = NULL;
				(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
				goto TSPI_lineMakeCall_return;
			}
			LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_HTTPAUTH succeeded"));

			// use the following code to disable SSL validation
			//ret = curl_easy_setopt(easyhandle, CURLOPT_SSL_VERIFYPEER, 0);
			//if (ret != CURLE_OK) {
			//	LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_SSL_VERIFYPEER=0 failed: %s",curl_easy_strerror(ret)));
			//	curl_easy_cleanup(easyhandle);
			//	pLine->htCall = NULL;
			//	(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
			//	goto TSPI_lineMakeCall_return;
			//}
			//LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_SSL_VERIFYPEER=0 succeeded"));

			if (iUseWindowsCertStore) {
				int i;
				LOG((5,"TSPI_lineMakeCall: export Windows' certificate store into a file"));
				// set temporary files location
				i = getTemporaryFilename(glpCAFileName,sizeof(glpCAFileName),CACERT_FILENAME);
				if (i) {
					LOG((1,"TSPI_lineMakeCall: getTemporaryFilename failed: %d", i));
					curl_easy_cleanup(easyhandle);
					pLine->htCall = NULL;
					(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
					goto TSPI_lineMakeCall_return;
				}
				// dump Windows certificate store to temporary file
				i = exportCertificates(glpCAFileName);
				if (i) {
					LOG((1,"TSPI_lineMakeCall: exportCertificates to %s failed: %d", i));
					curl_easy_cleanup(easyhandle);
					pLine->htCall = NULL;
					(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
					goto TSPI_lineMakeCall_return;
				}

				ret = curl_easy_setopt(easyhandle, CURLOPT_CAINFO, glpCAFileName);
				if (ret != CURLE_OK) {
					LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_CAINFO=%s failed: %s", glpCAFileName, curl_easy_strerror(ret)));
					curl_easy_cleanup(easyhandle);
					pLine->htCall = NULL;
					(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
					goto TSPI_lineMakeCall_return;
				}
				LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_CAINFO=%s succeeded", glpCAFileName));
			} else {
				LOG((5,"TSPI_lineMakeCall: using provided certificate file"));
				// szConfigCa = "c:\\cert.pem";
				ret = curl_easy_setopt(easyhandle, CURLOPT_CAINFO, szConfigCa);
				if (ret != CURLE_OK) {
					LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_CAINFO=%s failed: %s", szConfigCa, curl_easy_strerror(ret)));
					curl_easy_cleanup(easyhandle);
					pLine->htCall = NULL;
					(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
					goto TSPI_lineMakeCall_return;
				}
				LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_CAINFO=%s succeeded", szConfigCa));
			}

//			DebugBreak();
			szCurrentUri = szConfigUri;
			while (1) {
				if (szNextUri=strchr(szCurrentUri,'#')) {
					*szNextUri='\0';
					szNextUri++;
					LOG((3,"TSPI_lineMakeCall: URI seperator found! first URI=%s, other URI(s)=%s",szCurrentUri,szNextUri));
				} else {
					LOG((3,"TSPI_lineMakeCall: URI seperator not found: last URI=%s",szCurrentUri));
				}
				
				// replace %N (if found) with number
				for (p = szCurrentUri; *p != 0; p++) {
					if ( (*p == '%') && ( (*(p+1) == 'N') || (*(p+1) == 'n') ) ) {
						LOG((3,"TSPI_lineMakeCall: found %%N in current URI at position %d", p-szCurrentUri));
						break;
					}
				}
				if (*p == 0) {
					// %N was not found
					_snprintf(szFinalUri, MAX_REGKEYVAL_LENGTH, "%s", szCurrentUri);
					szFinalUri[MAX_REGKEYVAL_LENGTH - 1] = '\0';
				} else {
					// %N was found
					escaped_number = curl_easy_escape(easyhandle, szParsedNumber, 0);
					if (escaped_number == NULL) {
						LOG((1,"TSPI_lineMakeCall: curl_easy_escape '%s' failed.",szParsedNumber));
						curl_easy_cleanup(easyhandle);
						pLine->htCall = NULL;
						(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
						goto TSPI_lineMakeCall_return;
					}
					LOG((3,"TSPI_lineMakeCall: curl_easy_escape succeeded, escaped number is %s", escaped_number));

					*p = '\0';
					p += 2;
					_snprintf(szFinalUri, MAX_REGKEYVAL_LENGTH, "%s%s%s", 
						szCurrentUri,
						escaped_number,
						p);
					szFinalUri[MAX_REGKEYVAL_LENGTH - 1] = '\0';
					curl_free(escaped_number);
				}
				LOG((3,"TSPI_lineMakeCall: final URI: %s", szFinalUri));

				// now we have the URI in szFinalUri --> perform http request
				ret = curl_easy_setopt(easyhandle, CURLOPT_URL, szFinalUri);
				if (ret != CURLE_OK) {
					// an error occurred as <curl/curl.h> defines. See the libcurl-errors(3) man page for the 
					// full list with descriptions.
					LOG((1,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_URL failed: %s",curl_easy_strerror(ret)));
					curl_easy_cleanup(easyhandle);
					pLine->htCall = NULL;
					(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
					goto TSPI_lineMakeCall_return;
				}
				LOG((3,"TSPI_lineMakeCall: curl_easy_setopt CURLOPT_URL to %s succeeded", szFinalUri));

				ret = curl_easy_perform(easyhandle);
				// curl was not configured to store the received data, thus it will generate CURLE_WRITE_ERROR
				if (ret!=CURLE_OK && ret!=CURLE_WRITE_ERROR && ret!=CURLE_OPERATION_TIMEOUTED) {
					// an error occurred as <curl/curl.h> defines. See the libcurl-errors(3) man page for the 
					// full list with descriptions.
					LOG((1,"TSPI_lineMakeCall: curl_easy_perform failed: %d=%s",ret,curl_easy_strerror(ret)));
					curl_easy_cleanup(easyhandle);
					if (ret = CURLE_COULDNT_CONNECT) {
						// e.g. no server listening or server is down
						LOG((3,"TSPI_lineMakeCall: Sending asynch completion"));
						(*gpfnCompletionProc)(dwRequestID, 0);
						LOG((3,"TSPI_lineMakeCall: Sending LINECALLSTATE_DIALING"));
						SetCallState (pLine, LINECALLSTATE_DIALING, 0);
						LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_NODIALTONE"));
						SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_NODIALTONE);
						LOG((3,"TSPI_lineMakeCall: Sending LINECALLSTATE_IDLE"));
						SetCallState (pLine, LINECALLSTATE_IDLE, 0);
						goto TSPI_lineMakeCall_return;
					} else {
						pLine->htCall = NULL;
						(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
						goto TSPI_lineMakeCall_return;
					}
				}
				LOG((3,"TSPI_lineMakeCall: curl_easy_perform succeeded"));

				ret = curl_easy_getinfo (easyhandle, CURLINFO_RESPONSE_CODE, &responseCode);
				LOG((3,"TSPI_lineMakeCall: CURLINFO_RESPONSE_CODE=%ld", responseCode));

				if (szNextUri) {
					szCurrentUri = szNextUri;
				} else {
					break;
				}
			}

			LOG((3,"TSPI_lineMakeCall: curl_easy_cleanup ... "));
			curl_easy_cleanup(easyhandle);
			LOG((3,"TSPI_lineMakeCall: curl_easy_cleanup ... done"));
		} else {
			LOG((1,"TSPI_lineMakeCall: curl_easy_init failed"));
			pLine->htCall = NULL;
			LOG((1,"TSPI_lineMakeCall: LINEERR_OPERATIONFAILED"));
			(*gpfnCompletionProc)(dwRequestID, LINEERR_OPERATIONFAILED);
			goto TSPI_lineMakeCall_return;
		}

	}

	//
    // Complete the requests & set the initial call state
    // We ignore HTTP response code and always simluate a successive call

	LOG((3,"TSPI_lineMakeCall: Sending asynch completion"));
    (*gpfnCompletionProc)(dwRequestID, 0);

	LOG((3,"TSPI_lineMakeCall: Sending LINECALLSTATE_DIALING"));
	SetCallState (pLine, LINECALLSTATE_DIALING, 0);
	//LOG((3,"TSPI_lineMakeCall: sleep(3)")); Sleep(3000);

	switch (responseCode) {
		case 0:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_NODIALTONE"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_NODIALTONE);
			break;
		case 200:
			LOG((3,"TSPI_lineMakeCall: 200 -> Sending LINECALLSTATE_CONNECTED"));
			SetCallState (pLine, LINECALLSTATE_CONNECTED, 0);
			break;
		//case 401:
		//	LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/ LINEDISCONNECTMODE_DESTINATIONBARRED"));
		//	SetCallState (pLine, LINECALLSTATE_DISCONNECTED,  LINEDISCONNECTMODE_REJECT);
		//	break;
		case 403:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_BLOCKED"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_BLOCKED);
			break;
		case 404:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_BADADDRESS"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_BADADDRESS);
			break;
		case 408:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_UNREACHABLE"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_UNREACHABLE);
			break;
		case 486:
			LOG((3,"TSPI_lineMakeCall: 486 -> Sending LINECALLSTATE_BUSY"));
			SetCallState (pLine, LINECALLSTATE_BUSY, 0);
			break;
		case 500:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_OUTOFORDER"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_OUTOFORDER);
			break;
		case 503:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_CONGESTION"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_CONGESTION);
			break;
		case 603:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_REJECT"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_REJECT);
			break;
		default:
			LOG((3,"TSPI_lineMakeCall: 0 -> Sending LINECALLSTATE_DISCONNECTED/LINEDISCONNECTMODE_TEMPFAILURE"));
			SetCallState (pLine, LINECALLSTATE_DISCONNECTED, LINEDISCONNECTMODE_TEMPFAILURE);
			break;
	}
	LOG((3,"TSPI_lineMakeCall: Sending LINECALLSTATE_IDLE"));
	SetCallState (pLine, LINECALLSTATE_IDLE, 0);

TSPI_lineMakeCall_return:

	LOG((3,"TSPI_lineMakeCall: leaving ..."));
    return (Epilog (&info, dwRequestID));
}


LONG
TSPIAPI
TSPI_lineNegotiateTSPIVersion(
    DWORD   dwDeviceID,
    DWORD   dwLowVersion,
    DWORD   dwHighVersion,
    LPDWORD lpdwTSPIVersion
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwDeviceID,        dwDeviceID      },
        { "dwLowVersion",       dwLowVersion    },
        { "dwHighVersion",      dwHighVersion   },
        { "lpdwTSPIVersion",    lpdwTSPIVersion }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineNegotiateTSPIVersion",
        4,
        params
    };
#endif

    Prolog (&info);

	// version 3.0 to allow MSP usage
	//

    *lpdwTSPIVersion = 0x00030000;
//    *lpdwTSPIVersion = 0x00020000;
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineOpen(
    DWORD       dwDeviceID,
    HTAPILINE   htLine,
    LPHDRVLINE  lphdLine,
    DWORD       dwTSPIVersion,
    LINEEVENT   lpfnEventProc
    )
{
    LONG        lResult;
    PDRVLINE    pLine;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwDeviceID,    dwDeviceID      },
        { "htLine",         htLine          },
        { "lphdLine",       lphdLine        },
        { "dwTSPIVersion",  dwTSPIVersion   },
        { "lpfnEventProc",  lpfnEventProc   }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineOpen",
        5,
        params
    };
#endif


    Prolog (&info);

    if ((pLine = DrvAlloc (sizeof (DRVLINE))))
    {
        pLine->htLine       = htLine;
        pLine->pfnEventProc = lpfnEventProc;
        pLine->dwDeviceID   = dwDeviceID;

        *lphdLine = (HDRVLINE) pLine;

        lResult = 0;
    }
    else
    {
        lResult = LINEERR_NOMEM;
    }

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_lineSetDefaultMediaDetection(
    HDRVLINE    hdLine,
    DWORD       dwMediaModes
    )
{
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszhdLine,        hdLine       },
        { "dwMediaModes",   dwMediaModes }
    };
    FUNC_INFO   info =
    {
        "TSPI_lineSetDefaultMediaDetection",
        2,
        params
    };
#endif


    //
    // This func is really a no-op for us, since we don't look
    // for incoming calls (though we do say we support them to
    // make apps happy)
    //

    Prolog (&info);
    return (Epilog (&info, 0));
}


//
// ------------------------- TSPI_providerXxx funcs ---------------------------
//

LONG
TSPIAPI
TSPI_providerConfig(
    HWND    hwndOwner,
    DWORD   dwPermanentProviderID
    )
{
    //
    // Although this func is never called by TAPI v2.0, we export
    // it so that the Telephony Control Panel Applet knows that it
    // can configure this provider via lineConfigProvider(),
    // otherwise Telephon.cpl will not consider it configurable
    //

    return 0;
}


LONG
TSPIAPI
TSPI_providerGenericDialogData(
    DWORD_PTR           dwObjectID,
    DWORD               dwObjectType,
    LPVOID              lpParams,
    DWORD               dwSize
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "dwObjectID",     dwObjectID      },
        { "dwObjectType",   dwObjectType    },
        { "lpParams",       lpParams        },
        { "dwSize",         dwSize          }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerGenericDialogData",
        4,
        params
    };
#endif


    Prolog (&info);
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_providerInit(
    DWORD               dwTSPIVersion,
    DWORD               dwPermanentProviderID,
    DWORD               dwLineDeviceIDBase,
    DWORD               dwPhoneDeviceIDBase,
    DWORD_PTR           dwNumLines,
    DWORD_PTR           dwNumPhones,
    ASYNC_COMPLETION    lpfnCompletionProc,
    LPDWORD             lpdwTSPIOptions
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "dwTSPIVersion",          dwTSPIVersion           },
        { gszdwPermanentProviderID, dwPermanentProviderID   },
        { "dwLineDeviceIDBase",     dwLineDeviceIDBase      },
        { "dwPhoneDeviceIDBase",    dwPhoneDeviceIDBase     },
        { "dwNumLines",             dwNumLines              },
        { "dwNumPhones",            dwNumPhones             },
        { "lpfnCompletionProc",     lpfnCompletionProc      }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerInit",
        7,
        params
    };
#endif

    Prolog (&info);
	gdwPermanentProviderID = dwPermanentProviderID;
    gdwLineDeviceIDBase    = dwLineDeviceIDBase;
    gpfnCompletionProc     = lpfnCompletionProc;
	// we want multiple calls at the same time
    //*lpdwTSPIOptions = LINETSPIOPTION_NONREENTRANT;

	return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_providerInstall(
    HWND    hwndOwner,
    DWORD   dwPermanentProviderID
    )
{
    //
    // Although this func is never called by TAPI v2.0, we export
    // it so that the Telephony Control Panel Applet knows that it
    // can add this provider via lineAddProvider(), otherwise
    // Telephon.cpl will not consider it installable
    //
    //

#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwPermanentProviderID, dwPermanentProviderID   }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerInstall",
        1,
        params
    };
#endif

    Prolog (&info);

	return (Epilog (&info, 0));
}


LONG
TSPIAPI
TSPI_providerRemove(
    HWND    hwndOwner,
    DWORD   dwPermanentProviderID
    )
{
	LOG((5,"TSPI_providerRemove: entering ..."));

	//
    // Although this func is never called by TAPI v2.0, we export
    // it so that the Telephony Control Panel Applet knows that it
    // can remove this provider via lineRemoveProvider(), otherwise
    // Telephon.cpl will not consider it removable
    //

	LOG((5,"TSPI_providerRemove: leaving ..."));

	return 0;
}


LONG
TSPIAPI
TSPI_providerShutdown(
    DWORD   dwTSPIVersion,
    DWORD   dwPermanentProviderID
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "dwTSPIVersion",          dwTSPIVersion },
        { gszdwPermanentProviderID, dwPermanentProviderID   }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerShutdown",
        2,
        params
    };
#endif


    Prolog (&info);

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TSPI_providerEnumDevices(
    DWORD       dwPermanentProviderID,
    LPDWORD     lpdwNumLines,
    LPDWORD     lpdwNumPhones,
    HPROVIDER   hProvider,
    LINEEVENT   lpfnLineCreateProc,
    PHONEEVENT  lpfnPhoneCreateProc
    )
{
   HKEY     hKey;
   DWORD    dwNumLines, dwDataType, dwDataSize;

#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { gszdwPermanentProviderID, dwPermanentProviderID   },
        { "lpdwNumLines",           lpdwNumLines            },
        { "lpdwNumPhones",          lpdwNumPhones           },
        { "hProvider",              hProvider               },
        { "lpfnLineCreateProc",     lpfnLineCreateProc      },
        { "lpfnPhoneCreateProc",    lpfnPhoneCreateProc     }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerEnumDevices",
        6,
        params
    };
#endif

    Prolog (&info);

	gpfnLineCreateProc = lpfnLineCreateProc;
	ghProvider = hProvider;

	//
   // Retrieve the number of devices we're
   // configured for from our registry section
   //

   RegOpenKeyEx(
       HKEY_LOCAL_MACHINE,
       gszHttpTapiKeyFull,
       0,
       KEY_ALL_ACCESS,
       &hKey
       );

   dwDataSize = sizeof(dwNumLines);
   dwNumLines = 0;

   RegQueryValueEx(
       hKey,
       gszHttpTapiNumLines,
       0,
       &dwDataType,
       (LPBYTE) &dwNumLines,
       &dwDataSize
       );

   RegCloseKey (hKey);

   	// verify license
	set_gdwNumberOfLines(1);	

   if (dwNumLines > gdwNumberOfLines) {
	   dwNumLines = gdwNumberOfLines;
   }

   *lpdwNumLines  = dwNumLines;
   *lpdwNumPhones = 0;

   return (Epilog (&info, 0));
}


LONG
TSPIAPI
TSPI_providerUIIdentify(
    LPWSTR   lpszUIDLLName
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "lpsUIDLLName",  lpszUIDLLName }
    };
    FUNC_INFO   info =
    {
        "TSPI_providerUIIdentify",
        1,
        params
    };
#endif


    Prolog (&info);
    My_lstrcpyW(lpszUIDLLName, L"HttpTapi.tsp");
    return (Epilog (&info, lResult));
}


//
// ---------------------------- TUISPI_xxx funcs ------------------------------
//

LONG
TSPIAPI
TUISPI_lineConfigDialog(
    TUISPIDLLCALLBACK   lpfnUIDLLCallback,
    DWORD               dwDeviceID,
    HWND                hwndOwner,
    LPCWSTR             lpszDeviceClass
    )
{
    char        szDeviceClass[128];
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "lpfnUIDLLCallback",   lpfnUIDLLCallback },
        { gszdwDeviceID,         dwDeviceID        },
        { gszhwndOwner,          hwndOwner         },
        { "lpszDeviceClass",     szDeviceClass     }
    };
    FUNC_INFO   info =
    {
        "TUISPI_lineConfigDialog",
        4,
        params
    };
#endif

	LOG((5,"TUISPI_lineConfigDialog: ..."));
    if (lpszDeviceClass)
    {
        WideCharToMultiByte(
            CP_ACP,
            0,
            lpszDeviceClass,
            -1,
            (LPSTR) szDeviceClass,
            128,
            NULL,
            NULL
            );
    }

    Prolog (&info);

    DialogBoxParam(
        ghInst,
#ifdef LOGGING
        MAKEINTRESOURCE(IDD_DIALOG1_DEBUG),
#else
		MAKEINTRESOURCE(IDD_DIALOG1),
#endif
        hwndOwner,
        (DLGPROC) ConfigDlgProc,
        0
        );

	LOG((5,"TUISPI_lineConfigDialog: leaving ..."));
    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TUISPI_providerConfig(
    TUISPIDLLCALLBACK   lpfnUIDLLCallback,
    HWND                hwndOwner,
    DWORD               dwPermanentProviderID
    )
{
    LONG        lResult = 0;
#ifdef LOGGING
    FUNC_PARAM  params[] =
    {
        { "lpfnUIDLLCallback",      lpfnUIDLLCallback },
        { gszhwndOwner,             hwndOwner    },
        { gszdwPermanentProviderID, dwPermanentProviderID   }
    };
    FUNC_INFO   info =
    {
        "TUISPI_providerConfig",
        3,
        params
    };
#endif


    Prolog (&info);


    DialogBoxParam(
        ghInst,
#ifdef LOGGING
        MAKEINTRESOURCE(IDD_DIALOG1_DEBUG),
#else
		MAKEINTRESOURCE(IDD_DIALOG1),
#endif
        hwndOwner,
        (DLGPROC) ConfigDlgProc,
        0
        );

    return (Epilog (&info, lResult));
}


LONG
TSPIAPI
TUISPI_providerInstall(
    TUISPIDLLCALLBACK   lpfnUIDLLCallback,
    HWND                hwndOwner,
    DWORD               dwPermanentProviderID
    )
{
    LONG    lResult;


	LOG((5,"TUISPI_providerInstall: entering ..."));

		if ((lResult = ProviderInstall ("HttpTapi.tsp", TRUE)) == 0)
    {
        DialogBoxParam(
            ghInst,
#ifdef LOGGING
        MAKEINTRESOURCE(IDD_DIALOG1_DEBUG),
#else
		MAKEINTRESOURCE(IDD_DIALOG1),
#endif
            hwndOwner,
            (DLGPROC) ConfigDlgProc,
            0
            );
    }

    return lResult;
}


LONG
TSPIAPI
TUISPI_providerRemove(
    TUISPIDLLCALLBACK   lpfnUIDLLCallback,
    HWND                hwndOwner,
    DWORD               dwPermanentProviderID
    )
{
    //HKEY    hKey;

	LOG((5,"TUISPI_providerRemove: entering ..."));

	//
    // Clean up our registry section
    //

    //RegOpenKeyExA(
    //    HKEY_LOCAL_MACHINE,
    //    gszHttpTapiKeyBase,
    //    0,
    //    KEY_ALL_ACCESS,
    //    &hKey
    //    );

    //RegDeleteKeyA (hKey, gszHttpTapiKey);
    //RegCloseKey (hKey);

	LOG((5,"TUISPI_providerRemove: leaving ..."));

    return 0;
}


#pragma warning (default:4047)


//
// ---------------------- Misc private support routines -----------------------
//

LPWSTR
PASCAL
My_lstrcpyW(
    WCHAR   *pString1,
    WCHAR   *pString2
    )
{
    WCHAR *p = pString1;


    for (; (*p = *pString2); p++, pString2++);
    return pString1;
}


void
PASCAL
EnableChildren(
    HWND    hwnd,
    BOOL    bEnable
    )
{
    int i;
    static int aiControlIDs[] =
    {
        IDC_DEVICES,
        IDC_NAME,
        IDC_URI,
        IDC_CA,
        IDC_REMOVE,
        IDC_COMBO1,
        0
    };

	LOG((5, "EnableChildren: %s", bEnable?"TRUE":"FALSE"));

    for (i = 0; aiControlIDs[i]; i++)
    {
        EnableWindow (GetDlgItem (hwnd, aiControlIDs[i]), bEnable);
    }
	if (giUseWindowsCertStore) {
		EnableWindow(GetDlgItem(hwnd, IDC_CA), FALSE);
	}

}


void
PASCAL
SelectDevice(
    HWND    hwnd,
    LRESULT     iDevice
    )
{
    SendDlgItemMessage (hwnd, IDC_DEVICES, LB_SETCURSEL, iDevice, 0);
    PostMessage(hwnd, WM_COMMAND, IDC_DEVICES | (LBN_SELCHANGE << 16), 0);
}


void saveLicense(char *szencryptedLicense) {
	HKEY    hKey;
	RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		gszHttpTapiKeyFull,
		0,
		KEY_ALL_ACCESS,
		&hKey
		);
	RegSetValueEx(
		hKey,
		gszHttpTapiLicense,
		0,
		REG_SZ,
		(LPBYTE) szencryptedLicense,
		lstrlen (szencryptedLicense) + 1
		);
}


BOOL
CALLBACK
LicenseDlgProc(
    HWND    hwnd,
    UINT    msg,
    WPARAM  wParam,
    LPARAM  lParam
    )
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
		LOG((3,"LicenseDlgProc: WM_INITDIALOG received, verify license ..."));

		// verify license
		set_gdwNumberOfLines(0);	

		LOG((3,"LicenseDlgProc: WM_INITDIALOG received, verify license ... done"));

		if (gLicenseString == NULL) {
			// no license found
			SetDlgItemText(hwnd, IDC_NAME, "--- license not found ---");
			SetDlgItemText(hwnd, IDC_COMPANY, "please enter valid license string");
		} else {
			// display license info
			SetDlgItemText(hwnd, IDC_NAME, gLicense.name);
			SetDlgItemText(hwnd, IDC_COMPANY, gLicense.company);
			SetDlgItemText(hwnd, IDC_ADDRESS, gLicense.address);
			SetDlgItemText(hwnd, IDC_VALIDUNTIL, gLicense.validUntil);
			SetDlgItemText(hwnd, IDC_NUMBEROFLINES, gLicense.numberOfLines);
		}
        
        break;
    }
    case WM_COMMAND:
    {
		char	szencryptedLicense[MAX_LICENSE_LENGTH];
		int ret;

		LOG((3,"LicenseDlgProc: WM_COMMAND received"));

        switch (LOWORD((DWORD)wParam))
        {
        case IDC_APPLY:
			LOG((3,"LicenseDlgProc: WM_COMMAND - IDC_APPLY received"));
			GetDlgItemText (hwnd, IDC_LICENSE, szencryptedLicense, sizeof(szencryptedLicense));
			if (strlen(szencryptedLicense) == 0)
				break;
			LOG((3,"License: decrypting license ..."));
			ret = decryptLicense(&gLicense, szencryptedLicense);
			LOG((3,"License: decrypting license ... done"));
			if (ret) {
				// error decrypting license
				LOG((3,"License: invalid license ..."));
				MessageBox(0, 
					"License is invalid - please configure a valid license!", 
					"HttpTapi", 
					MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
			} else if (strlen(gLicense.validUntil) == 0) {
				// no validity date -> license does not expire
				LOG((3,"License: license does not expire ..."));
				gdwNumberOfLines = gLicense.iNumberOfLines;
				saveLicense(szencryptedLicense);
				// display license info
				SetDlgItemText(hwnd, IDC_NAME, gLicense.name);
				SetDlgItemText(hwnd, IDC_COMPANY, gLicense.company);
				SetDlgItemText(hwnd, IDC_ADDRESS, gLicense.address);
				SetDlgItemText(hwnd, IDC_VALIDUNTIL, gLicense.validUntil);
				SetDlgItemText(hwnd, IDC_NUMBEROFLINES, gLicense.numberOfLines);
				MessageBox(0, 
					"Sucessfully imported license!", 
					"HttpTapi", 
					MB_OK | MB_ICONINFORMATION | MB_SERVICE_NOTIFICATION);
			} else {
				// verify if license is still valid
				SYSTEMTIME currentSystemTime, licenseSystemTime;
				GetLocalTime(&currentSystemTime);
				GetLocalTime(&licenseSystemTime); // workaround to init the structure :-)
				LOG((3,"License: parsing validity date ..."));
				if (sscanf_s(gLicense.validUntil, 
					"%04u-%02u-%02u", &licenseSystemTime.wYear, 
					&licenseSystemTime.wMonth, &licenseSystemTime.wDay) != 3) {
						// error parsing date
						LOG((3,"License: invalid license date ..."));
						MessageBox(0, "Wrong license validity - please configure a valid license!", 
							"HttpTapi", MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
				} else {
					// compare timestamps
					FILETIME currentFileTime, licenseFileTime;
					SystemTimeToFileTime(&currentSystemTime, &currentFileTime);
					SystemTimeToFileTime(&licenseSystemTime, &licenseFileTime);
					if (CompareFileTime(&currentFileTime,&licenseFileTime) == 1) {
						// license expired
						LOG((3,"License: licensed expired at %s",gLicense.validUntil));
						MessageBox(0, "License expired - please configure a valid license!", 
							"HttpTapi", MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
					} else {
						// license valid
						LOG((3,"License: licensed still valid (till %s (%04u-%02u-%02u))",gLicense.validUntil,
							licenseSystemTime.wYear, licenseSystemTime.wMonth, licenseSystemTime.wDay));
						gdwNumberOfLines = gLicense.iNumberOfLines;
						saveLicense(szencryptedLicense);
						// display license info
						SetDlgItemText(hwnd, IDC_NAME, gLicense.name);
						SetDlgItemText(hwnd, IDC_COMPANY, gLicense.company);
						SetDlgItemText(hwnd, IDC_ADDRESS, gLicense.address);
						SetDlgItemText(hwnd, IDC_VALIDUNTIL, gLicense.validUntil);
						SetDlgItemText(hwnd, IDC_NUMBEROFLINES, gLicense.numberOfLines);
						MessageBox(0, 
							"Sucessfully imported license!", 
							"HttpTapi", 
							MB_OK | MB_ICONINFORMATION | MB_SERVICE_NOTIFICATION);
					}
				}
			}
            break;

        case IDCANCEL:
			LOG((3,"LicenseDlgProc: WM_COMMAND - IDCANCEL received"));
            EndDialog (hwnd, 0);
			break;

        } // switch (LOWORD((DWORD)wParam))

        break;
    }
    } // switch (msg)

    return FALSE;
}


BOOL
CALLBACK
ConfigDlgProc(
    HWND    hwnd,
    UINT    msg,
    WPARAM  wParam,
    LPARAM  lParam
    )
{
    static  HKEY    hHttpTapiKey;

    DWORD   dwDataSize;
    DWORD   dwDataType;


    switch (msg)
    {
    case WM_INITDIALOG:
    {
        char   *pBufName, *pBufUri, *pBufCa;
        DWORD   i, iNumLines;

		LOG((3,"ConfigDlgProc: WM_INITDIALOG received"));

		// disable the LICENSE button for fixed licenses
#ifdef SINGLELINE
		EnableWindow(GetDlgItem(hwnd, IDC_LICENSE), FALSE);
#endif
#ifdef NOLICENSE
		EnableWindow(GetDlgItem(hwnd, IDC_LICENSE), FALSE);
#endif

        // Create or open our configuration key in the registry.  If the
        // create fails it may well be that the current user does not
        // have write access to this portion of the registry, so we'll
        // just show a "read only" dialog and not allow user to make any
        // changes
        //

        {
            LONG    lResult;
            DWORD   dwDisposition;


            if ((lResult = RegCreateKeyEx(
                    HKEY_LOCAL_MACHINE,
                    gszHttpTapiKeyFull,
                    0,
                    "",
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    (LPSECURITY_ATTRIBUTES) NULL,
                    &hHttpTapiKey,
                    &dwDisposition

                    )) != ERROR_SUCCESS)
            {
                LOG((
                    1,
                    "RegCreateKeyEx(%s,ALL_ACCESS) failed, err=%d",
                    gszHttpTapiKeyFull,
                    lResult
                    ));

                if ((lResult = RegOpenKeyEx(
                        HKEY_LOCAL_MACHINE,
                        gszHttpTapiKeyFull,
                        0,
                        KEY_QUERY_VALUE,
                        &hHttpTapiKey

                        )) != ERROR_SUCCESS)
                {
                    LOG((
                        1,
                        "RegOpenKeyEx(%s,ALL_ACCESS) failed, err=%d",
                        gszHttpTapiKeyFull,
                        lResult
                        ));

                    EndDialog (hwnd, 0);
                    return FALSE;
                }

                {
                    int i;
                    static int aiControlIDs[] =
                    {
                        IDC_NAME,
                        IDC_URI,
                        IDC_CA,
                        IDC_ADD,
                        IDC_REMOVE,
                        IDOK,
                        0
                    };


                    for (i = 0; aiControlIDs[i]; i++)
                    {
                        EnableWindow(
                            GetDlgItem (hwnd, aiControlIDs[i]),
                            FALSE
                            );
                    }
                }
            }
        }


        //
        // Retrieve our configuration info from the registry
        //

		LOG((3,"ConfigDlgProc: WM_INITDIALOG: retrieving configuration from registry"));

        dwDataSize = sizeof(iNumLines);
        iNumLines = 0;

        RegQueryValueEx(
            hHttpTapiKey,
            gszHttpTapiNumLines,
            0,
            &dwDataType,
            (LPBYTE) &iNumLines,
            &dwDataSize
            );

		LOG((3,"ConfigDlgProc: WM_INITDIALOG: NumLines=%d",iNumLines));

        dwDataSize = sizeof(giUseWindowsCertStore);
        giUseWindowsCertStore = 0;

        RegQueryValueEx(
            hHttpTapiKey,
            gszHttpTapiCertStore,
            0,
            &dwDataType,
            (LPBYTE) &giUseWindowsCertStore,
            &dwDataSize
            );

		LOG((3,"ConfigDlgProc: WM_INITDIALOG: %s=%d",gszHttpTapiCertStore,giUseWindowsCertStore));

		CheckDlgButton(hwnd, IDC_CERTSTORE, giUseWindowsCertStore);
		if (giUseWindowsCertStore) {
			EnableWindow(GetDlgItem(hwnd, IDC_CA), FALSE);
		}

		SendDlgItemMessage(
            hwnd,
            IDC_NAME,
            EM_LIMITTEXT,
            MAX_REGKEYVAL_LENGTH,
            0
            );

        SendDlgItemMessage(
            hwnd,
            IDC_URI,
            EM_LIMITTEXT,
            MAX_REGKEYVAL_LENGTH,
            0
            );

        SendDlgItemMessage(
            hwnd,
            IDC_CA,
            EM_LIMITTEXT,
            MAX_REGKEYVAL_LENGTH,
            0
            );

        if (!(pBufName = DrvAlloc (MAX_REGKEYVAL_LENGTH)))
        	break;
        if (!(pBufUri = DrvAlloc (MAX_REGKEYVAL_LENGTH)))
        	break;
        if (!(pBufCa = DrvAlloc (MAX_REGKEYVAL_LENGTH)))
        	break;

		// store the number of configured lines globally
		// so later we can compare if lines were added or closed

		giNumLines = iNumLines;
        for (i = 0; i < iNumLines; i++)
        {
            char            szLineN[MAX_REGKEYNAME_LENGTH];
            PDRVLINECONFIG  pLineConfig;
            LONG            lResult;

			LOG((3,"ConfigDlgProc: WM_INITDIALOG: reading lineconfig of line %d", i));

			if (!(pLineConfig = DrvAlloc (sizeof(DRVLINECONFIG)))) {
				LOG((1,"ConfigDlgProc: WM_INITDIALOG: error allocating memory for lineconfig of line %d", i));
				break;
			}

            // Read line name and config,
            // If there was a problem, skip this line
            //

			dwDataSize = MAX_REGKEYVAL_LENGTH;
			wsprintf (szLineN, "Line%dName", i);
            lResult = RegQueryValueEx(
                hHttpTapiKey,
                szLineN,
                0,
                &dwDataType,
                (LPBYTE) pBufName,
                &dwDataSize
                );
            if (0 != lResult) {
				LOG((1,"ConfigDlgProc: WM_INITDIALOG: error reading line name from registry"));
				*pBufName = 0;
			}
			LOG((3,"ConfigDlgProc: WM_INITDIALOG: line name: %s", pBufName));

			dwDataSize = MAX_REGKEYVAL_LENGTH;
			wsprintf (szLineN, "Line%dUri", i);
            lResult = RegQueryValueEx(
                hHttpTapiKey,
                szLineN,
                0,
                &dwDataType,
                (LPBYTE) pBufUri,
                &dwDataSize
                );
            if (0 != lResult) {
				LOG((1,"ConfigDlgProc: WM_INITDIALOG: error reading line URI from registry"));
				*pBufUri = 0;
			}
			LOG((3,"ConfigDlgProc: WM_INITDIALOG: line URI: %s", pBufUri));

			dwDataSize = MAX_REGKEYVAL_LENGTH;
			wsprintf (szLineN, "Line%dCa", i);
			lResult = RegQueryValueEx(
                hHttpTapiKey,
                szLineN,
                0,
                &dwDataType,
                (LPBYTE) pBufCa,
                &dwDataSize
                );
            if (0 != lResult) {
				LOG((1,"ConfigDlgProc: WM_INITDIALOG: error reading line CA from registry"));
				*pBufCa = 0;
			}
			LOG((3,"ConfigDlgProc: WM_INITDIALOG: line CA: %s", pBufCa));

            SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_ADDSTRING,
                0,
                (LPARAM) pBufName
                );

            SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_SETITEMDATA,
                i,
                (LPARAM) pLineConfig
                );

            strncpy (pLineConfig->szUri, pBufUri, MAX_REGKEYVAL_LENGTH-1);
			pLineConfig->szUri[MAX_REGKEYVAL_LENGTH-1] = '\0';
            strncpy (pLineConfig->szCa, pBufCa, MAX_REGKEYVAL_LENGTH-1);
			pLineConfig->szCa[MAX_REGKEYVAL_LENGTH-1] = '\0';
        }

        DrvFree (pBufName);
        DrvFree (pBufUri);
        DrvFree (pBufCa);

        if (iNumLines == 0)
        {
            EnableChildren (hwnd, FALSE);
        }
        else
        {
            SelectDevice (hwnd, 0);
        }

		// set example URIs
		SetDlgItemText(hwnd, IDC_SNOM, gszDefaultSnomUri);
		SetDlgItemText(hwnd, IDC_ASTERISK, gszDefaultAsteriskUri);
#ifdef LOGGING
		ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBO1),"0");
		ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBO1),"1");
		ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBO1),"2");
		ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBO1),"3");
		ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBO1),"4");
		ComboBox_AddString(GetDlgItem(hwnd, IDC_COMBO1),"5");
		ComboBox_SetCurSel(GetDlgItem(hwnd, IDC_COMBO1),getLogLevel());
#endif
		// verify license
		set_gdwNumberOfLines(0);
		//if (gdwNumberOfLines == 0 && ) {
		//	//broken or no license installed
		//	LOG((3,"ConfigDlgProc: invalid license or license not installed"));
		//	MessageBox(0, 
		//		"Error: License is invalid - please configure a valid license!", 
		//		"HttpTapi", 
		//		MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
		//	break;
		//}

		if (giNumLines > (int) gdwNumberOfLines) {
			//more lines than allowed by the license
			LOG((3,"ConfigDlgProc: more lines configured than allowed by license"));
			MessageBox(0, 
				"Note: You have configured more lines than your license allows. You can only use the number of lines defined in the license!", 
				"HttpTapi", 
				MB_OK | MB_ICONWARNING | MB_SERVICE_NOTIFICATION);
		}

		break;
    }
    case WM_COMMAND:
    {
        LRESULT             iSelection;
        PDRVLINECONFIG  pLineConfig;

		LOG((3,"ConfigDlgProc: WM_COMMAND received"));

        iSelection = SendDlgItemMessage(
            hwnd,
            IDC_DEVICES,
            LB_GETCURSEL,
            0,
            0
            );

        pLineConfig = (PDRVLINECONFIG) SendDlgItemMessage(
            hwnd,
            IDC_DEVICES,
            LB_GETITEMDATA,
            (WPARAM) iSelection,
            0
            );

        switch (LOWORD((DWORD)wParam))
        {
        case IDC_DEVICES:

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_DEVICES received"));

			if (HIWORD(wParam) == LBN_SELCHANGE)
            {
				char buf[MAX_REGKEYVAL_LENGTH+1];

				LOG((3,"ConfigDlgProc: WM_COMMAND-IDC_DEVICES: LBN_SELCHANGE"));

				SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_GETTEXT,
                    iSelection,
                    (LPARAM) buf
                    );

                SetDlgItemText (hwnd, IDC_NAME, buf);
                SetDlgItemText (hwnd, IDC_URI, pLineConfig->szUri);
                SetDlgItemText (hwnd, IDC_CA, pLineConfig->szCa);
			}

			if (giUseWindowsCertStore) {
				EnableWindow(GetDlgItem(hwnd, IDC_CA), FALSE);
			}

            break;

        case IDC_NAME:

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_NAME received"));

            if ((HIWORD(wParam) == EN_CHANGE) && (iSelection != LB_ERR))
            {
                char    buf[MAX_REGKEYVAL_LENGTH + 1];


                GetDlgItemText (hwnd, IDC_NAME, buf, MAX_REGKEYVAL_LENGTH);

                SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_DELETESTRING,
                    iSelection,
                    0
                    );

                SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_INSERTSTRING,
                    iSelection,
                    (LPARAM) buf
                    );

                SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_SETCURSEL,
                    iSelection,
                    0
                    );

                SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_SETITEMDATA,
                    iSelection,
                    (LPARAM) pLineConfig
                    );
            }

            break;

        case IDC_URI:

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_URI received"));

            if ((HIWORD(wParam) == EN_CHANGE) && (iSelection != LB_ERR))
            {
                GetDlgItemText(
                    hwnd,
                    IDC_URI,
                    pLineConfig->szUri,
                    MAX_REGKEYVAL_LENGTH-1
                    );
            }

            break;

        case IDC_CA:

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_CA received"));

            if ((HIWORD(wParam) == EN_CHANGE) && (iSelection != LB_ERR))
            {
                GetDlgItemText(
                    hwnd,
                    IDC_CA,
                    pLineConfig->szCa,
                    MAX_REGKEYVAL_LENGTH-1
                    );
            }

            break;

        case IDC_ADD:
        {
            LRESULT             iNumLines;
			int				i = 2;
            char            szLineName[MAX_REGKEYVAL_LENGTH];
            PDRVLINECONFIG  pLineConfig;

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_ADD received"));

            if(!(pLineConfig = DrvAlloc (sizeof(DRVLINECONFIG))))
            	break;

            iNumLines = SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_GETCOUNT,
                0,
                0
                );

			if (iNumLines >= gdwNumberOfLines) {
				//no more lines allowed
				LOG((1,"ConfigDlgProc: no more lines allowed"));
				MessageBox(0, 
					"Error: You can not configure more lines than your license allows.!", 
					"HttpTapi", 
					MB_OK | MB_ICONERROR | MB_SERVICE_NOTIFICATION);
				break;
			}

            strncpy (szLineName, gszHttpTapiDefLineConfigParamsName,MAX_REGKEYVAL_LENGTH-1 );
			szLineName[MAX_REGKEYVAL_LENGTH-1] = '\0';
            strncpy (pLineConfig->szUri, gszHttpTapiDefLineConfigParamsUri,MAX_REGKEYVAL_LENGTH-1 );
			pLineConfig->szUri[MAX_REGKEYVAL_LENGTH-1] = '\0';
            strncpy (pLineConfig->szCa, gszHttpTapiDefLineConfigParamsCa,MAX_REGKEYVAL_LENGTH-1 );
			pLineConfig->szCa[MAX_REGKEYVAL_LENGTH-1] = '\0';

find_unique_line_name:

            if (SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_FINDSTRING,
                    (WPARAM) -1,
                    (LPARAM) szLineName

                    ) != LB_ERR)
            {
                wsprintf (szLineName, "%s (%d)", gszHttpTapiDefLineConfigParamsName, i++);
                goto find_unique_line_name;
            }

            SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_ADDSTRING,
                0,
                (LPARAM) szLineName
                );

            SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_SETITEMDATA,
                iNumLines,
                (LPARAM) pLineConfig
                );

            EnableChildren (hwnd, TRUE);

            SelectDevice (hwnd, iNumLines);

            SetFocus (GetDlgItem (hwnd, IDC_NAME));

            SendDlgItemMessage(
                hwnd,
                IDC_NAME,
                EM_SETSEL,
                0,
                (LPARAM) -1
                );

            break;
        }
        case IDC_REMOVE:
        {
            LRESULT iNumLines;

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_REMOVE received"));

            DrvFree (pLineConfig);

            iNumLines = SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_DELETESTRING,
                iSelection,
                0
                );

            if (iNumLines == 0)
            {
                SetDlgItemText (hwnd, IDC_NAME, "");
                SetDlgItemText (hwnd, IDC_URI, "");
                SetDlgItemText (hwnd, IDC_CA, "");

                EnableChildren (hwnd, FALSE);
            }
            else
            {
                SelectDevice (hwnd, 0);
            }

            break;
        }
        case IDOK:
        {
            int     i;
			LRESULT	iNumLines;
            char   *pBuf;
			DWORD dwDebugLevel;

		LOG((3,"ConfigDlgProc: WM_COMMAND - IDOK received"));

            //
            // Update the num lines & num phones values
            //

            if (!(pBuf = DrvAlloc (MAX_REGKEYVAL_LENGTH)))
            	break;

            iNumLines = SendDlgItemMessage(
                hwnd,
                IDC_DEVICES,
                LB_GETCOUNT,
                0,
                0
                );

            RegSetValueEx(
                hHttpTapiKey,
                gszHttpTapiNumLines,
                0,
                REG_DWORD,
                (LPBYTE) &iNumLines,
                sizeof(DWORD)
                );

			giUseWindowsCertStore = IsDlgButtonChecked(hwnd, IDC_CERTSTORE);
            RegSetValueEx(
                hHttpTapiKey,
                gszHttpTapiCertStore,
                0,
                REG_DWORD,
                (LPBYTE) &giUseWindowsCertStore,
                sizeof(DWORD)
                );

            //
            // For each installed device save it's config info
            //

            for (i = 0; i < iNumLines; i++)
            {
                char szLineName[MAX_REGKEYNAME_LENGTH];
                char szLineUri[MAX_REGKEYNAME_LENGTH];
                char szLineCa[MAX_REGKEYNAME_LENGTH];
                PDRVLINECONFIG pLineConfig;


                SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_GETTEXT,
                    i,
                    (LPARAM) pBuf
                    );

                pLineConfig = (PDRVLINECONFIG) SendDlgItemMessage(
                    hwnd,
                    IDC_DEVICES,
                    LB_GETITEMDATA,
                    i,
                    0
                    );

                wsprintf (szLineName, "Line%dName", i);
                wsprintf (szLineUri, "Line%dUri", i);
                wsprintf (szLineCa, "Line%dCa", i);

                RegSetValueEx(
                    hHttpTapiKey,
                    szLineName,
                    0,
                    REG_SZ,
                    (LPBYTE) pBuf,
                    lstrlen (pBuf) + 1
                    );
                RegSetValueEx(
                    hHttpTapiKey,
                    szLineUri,
                    0,
                    REG_SZ,
                    (LPBYTE) pLineConfig->szUri,
                    lstrlen (pLineConfig->szUri) + 1
                    );
                RegSetValueEx(
                    hHttpTapiKey,
                    szLineCa,
                    0,
                    REG_SZ,
                    (LPBYTE) pLineConfig->szCa,
                    lstrlen (pLineConfig->szCa) + 1
                    );

                DrvFree (pLineConfig);
            }

            DrvFree (pBuf);

			LOG((3,"old lines count: %d, new lines count: %d",giNumLines, iNumLines));
			// check if the number of lines was changed
			if (iNumLines != giNumLines) {
				MessageBox(0, 
					"You changed the number of configured lines! This "
					"means that you usually have to restart your TAPI "
					"applications to propagate the chances to the TAPI "
					"application!", 
					"HttpTapi", 
					MB_OK | MB_ICONINFORMATION | MB_SERVICE_NOTIFICATION);
				while (giNumLines < iNumLines ) {
					if (gpfnLineCreateProc) {
						LOG((3,"Adding line %d",giNumLines));
						gpfnLineCreateProc(0,0,LINE_CREATE,ghProvider,0,0);
					}
					giNumLines++;
				}
				while (giNumLines > iNumLines ) {
					if (gpfnLineCreateProc) {
						LOG((3,"Removing line %d (%d)",giNumLines,giNumLines + gdwLineDeviceIDBase - 1));
						gpfnLineCreateProc(0,0,LINE_REMOVE,giNumLines + gdwLineDeviceIDBase - 1,0,0);
					}
					giNumLines--;
				}
			}

			dwDebugLevel = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO1));
			setLogLevel(dwDebugLevel);

			RegSetValueEx(
                hHttpTapiKey,
                gszHttpTapiDebugLevel,
                0,
                REG_DWORD,
                (LPBYTE) &dwDebugLevel,
                sizeof(DWORD)
                );

            // fall thru to EndDialog...
        }
        case IDCANCEL:

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDCANCEL received"));

			RegCloseKey (hHttpTapiKey);
            EndDialog (hwnd, 0);
            break;

        case IDC_LICENSE:

			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_LICENSE received"));
			DialogBoxParam(
				ghInst,
				MAKEINTRESOURCE(IDD_DIALOG_LICENSE),
				hwnd,
				(DLGPROC) LicenseDlgProc,
				0
				);
            break;

		case IDC_CERTSTORE:
			LOG((3,"ConfigDlgProc: WM_COMMAND - IDC_CERTSTORE received"));
			if (IsDlgButtonChecked(hwnd, IDC_CERTSTORE)) {
				giUseWindowsCertStore = 1;
				EnableWindow(GetDlgItem(hwnd, IDC_CA), FALSE);
			} else {
				giUseWindowsCertStore = 0;
				EnableWindow(GetDlgItem(hwnd, IDC_CA), TRUE);
			}
			break;

		} // switch (LOWORD((DWORD)wParam))

		break;
    } // case WM_COMMAND
    } // switch (msg)

    return FALSE;
}


LPVOID
PASCAL
DrvAlloc(
    DWORD dwSize
    )
{
    return (LocalAlloc (LPTR, dwSize));
}


VOID
PASCAL
DrvFree(
    LPVOID lp
    )
{
    LocalFree (lp);
}


void
PASCAL
SetCallState(
    PDRVLINE    pLine,
    DWORD       dwCallState,
    DWORD       dwCallStateMode
    )
{
    if (dwCallState != pLine->dwCallState)
    {
        pLine->dwCallState     = dwCallState;
        pLine->dwCallStateMode = dwCallStateMode;

        (*pLine->pfnEventProc)(
            pLine->htLine,
            pLine->htCall,
            LINE_CALLSTATE,
            dwCallState,
            dwCallStateMode,
            pLine->dwMediaMode
            );
    }
}


LONG
PASCAL
ProviderInstall(
    char   *pszProviderName,
    BOOL    bNoMultipleInstance
    )
{
    LONG    lResult;

	LOG((5,"ProviderInstall: entering ..."));

    //
    // If only one installation instance of this provider is
    // allowed then we want to check the provider list to see
    // if the provider is already installed
    //

    if (bNoMultipleInstance)
    {
        LONG                (WINAPI *pfnGetProviderList)();
        DWORD               dwTotalSize, i;
        HINSTANCE           hTapi32;
        LPLINEPROVIDERLIST  pProviderList;
        LPLINEPROVIDERENTRY pProviderEntry;


        //
        // Load Tapi32.dll & get a pointer to the lineGetProviderList
        // func.  We don't want to statically link because this module
        // plays the part of both core SP & UI DLL, and we don't want
        // to incur the performance hit of automatically loading
        // Tapi32.dll when running as a core SP within Tapisrv.exe's
        // context.
        //

        if (!(hTapi32 = LoadLibrary ("tapi32.dll")))
        {
            LOG((
                1,
                "LoadLibrary(tapi32.dll) failed, err=%d",
                GetLastError()
                ));

            lResult = LINEERR_OPERATIONFAILED;
            goto ProviderInstall_return;
        }

        if (!(pfnGetProviderList = (LONG (WINAPI *)())GetProcAddress(
                hTapi32,
                (LPCSTR) "lineGetProviderList"
                )))
        {
            LOG((
                1,
                "GetProcAddr(lineGetProviderList) failed, err=%d",
                GetLastError()
                ));

            lResult = LINEERR_OPERATIONFAILED;
            goto ProviderInstall_unloadTapi32;
        }


        //
        // Loop until we get the full provider list
        //

        dwTotalSize = sizeof (LINEPROVIDERLIST);

        goto ProviderInstall_allocProviderList;

ProviderInstall_getProviderList:

        if ((lResult = (*pfnGetProviderList)(0x00020000, pProviderList)) != 0)
        {
            goto ProviderInstall_freeProviderList;
        }

        if (pProviderList->dwNeededSize > pProviderList->dwTotalSize)
        {
            dwTotalSize = pProviderList->dwNeededSize;

            LocalFree (pProviderList);

ProviderInstall_allocProviderList:

            if (!(pProviderList = LocalAlloc (LPTR, dwTotalSize)))
            {
                lResult = LINEERR_NOMEM;
                goto ProviderInstall_unloadTapi32;
            }

            pProviderList->dwTotalSize = dwTotalSize;

            goto ProviderInstall_getProviderList;
        }


        //
        // Inspect the provider list entries to see if this provider
        // is already installed
        //

        pProviderEntry = (LPLINEPROVIDERENTRY) (((LPBYTE) pProviderList) +
            pProviderList->dwProviderListOffset);

        for (i = 0; i < pProviderList->dwNumProviders; i++)
        {
            char   *pszInstalledProviderName = ((char *) pProviderList) +
                        pProviderEntry->dwProviderFilenameOffset,
                   *p;


            //
            // Make sure pszInstalledProviderName points at <filename>
            // and not <path>\filename by walking backeards thru the
            // string searching for last '\\'
            //

            p = pszInstalledProviderName +
                lstrlen (pszInstalledProviderName) - 1;

            for (; *p != '\\'  &&  p != pszInstalledProviderName; p--);

            pszInstalledProviderName =
                (p == pszInstalledProviderName ? p : p + 1);

            if (lstrcmpiA (pszInstalledProviderName, pszProviderName) == 0)
            {
                lResult = LINEERR_NOMULTIPLEINSTANCE;
                goto ProviderInstall_freeProviderList;
            }

            pProviderEntry++;
        }


        //
        // If here then the provider isn't currently installed,
        // so do whatever configuration stuff is necessary and
        // indicate SUCCESS
        //

        lResult = 0;


ProviderInstall_freeProviderList:

        LocalFree (pProviderList);

ProviderInstall_unloadTapi32:

        FreeLibrary (hTapi32);
    }
    else
    {
        //
        // Do whatever configuration stuff is necessary and return SUCCESS
        //

        lResult = 0;
    }

ProviderInstall_return:

    return lResult;
}


void
PASCAL
DropActiveCall(
    PDRVLINE    pLine
    )
{
	LOG((5,"DropActiveCall: entering ..."));

	LOG((5,"DropActiveCall: leaving ..."));
}
