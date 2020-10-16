/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name: crypt.c

Simple de-/encryption functions, e.g. to store passwords encrypted in the registry

--*/

#include <windows.h>
#include <Wincrypt.h>

#include "crypt.h"
#include "tapi_logging.h"

char* decryptString(const char *szencryptedString) {
	BOOL ret;
	DWORD bufflen;
	char *buff;
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;

	LOG((5,"decryptString ..."));

	ret = CryptStringToBinary(
		szencryptedString,
		0,
		CRYPT_STRING_BASE64,
		0,
		&bufflen,
		0,
		0);
	if (ret == FALSE) {
		LOG((1,"decryptString: error calculating base64-deconding buffer size"));
		return NULL;
	}

	if ( !(buff = (char *) LocalAlloc(LPTR, bufflen*sizeof(BYTE) + 1)) ) {
		LOG((1,"decryptString: error allocating %d bytes",
			bufflen*sizeof(BYTE) + 1));
		return NULL;
	}

	ret = CryptStringToBinary(
		szencryptedString,
		0,
		CRYPT_STRING_BASE64,
		(BYTE *) buff,
		&bufflen,
		0,
		0);
	if (ret == FALSE) {
		LOG((1,"decryptString: error while base64 decoding"));
		return NULL;
	}

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
				LOG((1,"decryptString: Error in AcquireContext (with new container) 0x%08x",GetLastError()));
				if (buff) LocalFree(buff);
				return NULL;
			}
		}
		else 
		{
			LOG((1,"decryptString: Error in AcquireContext 0x%08x",GetLastError()));
			if (buff) LocalFree(buff);
			return NULL;
		}
	}

	// Use the CryptImportKey function to import the PLAINTEXTKEYBLOB
	// BYTE array into the key container. The function returns a 
	// pointer to an HCRYPTKEY variable that contains the handle of
	// the imported key.

	if (!CryptImportKey(
		hProv,
		SimpleDesKeyBlob,
		sizeof(SimpleDesKeyBlob),
		0,
		CRYPT_EXPORTABLE,
		&hKey ) )
	{
		LOG((1,"decryptString: Error 0x%08x in importing the Des key",GetLastError()));
		if (buff) LocalFree(buff);
		if (hProv) CryptReleaseContext(hProv, 0);
		return NULL;
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
		LOG((1,"decryptString: Error 0x%08x during decryption",GetLastError()));
		if (buff) LocalFree(buff);
		if (hProv) CryptReleaseContext(hProv, 0);
		return NULL;
	}
	if (hProv) CryptReleaseContext(hProv, 0);

	// Note: We expect that original string was zero terminate before decoding,
	// so the decrypted string is also zero terminated.

	return buff;
	
};

char* encryptString(const char *szplainString) {
	// hProv:           Cryptographic service provider (CSP). This example
	//                  uses the Microsoft Enhanced Cryptographic 
	//                  Provider.
	// hKey:            Key to be used. In this example, you import the 
	//                  key as a PLAINTEXTKEYBLOB.
	HCRYPTPROV hProv  = (HCRYPTPROV) NULL;
	HCRYPTKEY hKey    = (HCRYPTKEY) NULL;

	DWORD bufflen;
	LPTSTR buff = 0;
	BYTE * pbData = 0;
	DWORD dwDataLen, dwBufLen;

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
				LOG((1,"encryptString: Error in AcquireContext (with new container) 0x%08x",GetLastError()));
				return NULL;
			}
		} else {
			LOG((1,"encryptString: Error in AcquireContext 0x%08x",GetLastError()));
			return NULL;
		}
	}
	LOG((5,"encryptString: AcquireContext succeeded"));

	// Use the CryptImportKey function to import the PLAINTEXTKEYBLOB
	// BYTE array into the key container. The function returns a 
	// pointer to an HCRYPTKEY variable that contains the handle of
	// the imported key.

	if (!CryptImportKey(
		hProv,
		SimpleDesKeyBlob,
		sizeof(SimpleDesKeyBlob),
		0,
		CRYPT_EXPORTABLE,
		&hKey ) )
	{
		LOG((1,"decryptString: Error 0x%08x in importing the Des key",GetLastError()));
		goto cleanup;
	}
	LOG((5,"encryptString: CryptImportKey succeeded"));

	// During encryption, the result can be longer then the input
	// Thus, calculate the needed buffer length
	dwBufLen = (DWORD) strlen(szplainString) + 1;
	if (!CryptEncrypt(
		hKey,			  //__in     HCRYPTKEY hKey,
		0,				  //__in     HCRYPTHASH hHash,
		TRUE,			  //__in     BOOL Final,
		0,				  //__in     DWORD dwFlags,
		0,				  //__inout  BYTE *pbData,
		&dwBufLen,		  //__inout  DWORD *pdwDataLen,
		0				  //__in     DWORD dwBufLen
		) )
	{
		LOG((1,"decryptString: Error 0x%08x during encryption calculation",GetLastError()));
		goto cleanup;
	}
	LOG((5,"encryptString: CryptEncrypt1 succeeded"));

	if ( dwBufLen < (strlen(szplainString) + 1) ) {
		dwBufLen = (DWORD) (strlen(szplainString) + 1);
	}
	if ( !(pbData = (BYTE *) LocalAlloc(LPTR, dwBufLen)) ) {
		LOG((1,"decryptString: error allocating %d bytes", dwBufLen));
		goto cleanup;
	}
	// copy the original into the new buffer as it will be destroyed during encrpytion
	dwDataLen = (DWORD) strlen(szplainString) + 1;
	memcpy(pbData, szplainString, dwDataLen);

	if (!CryptEncrypt(
		hKey,			  //__in     HCRYPTKEY hKey,
		0,				  //__in     HCRYPTHASH hHash,
		TRUE,			  //__in     BOOL Final,
		0,				  //__in     DWORD dwFlags,
		pbData,			  //__inout  BYTE *pbData,
		&dwDataLen,		  //__inout  DWORD *pdwDataLen,
		dwBufLen		  //__in     DWORD dwBufLen
		) )
	{
		LOG((1,"decryptString: Error 0x%08x during encryption"));
		goto cleanup;
	}
	LOG((5,"encryptString: CryptEncrypt2 succeeded"));

	// Encrypted Key steht nun pbData --> nun machen wir daraus Base64!
	// 1. calculate length
	if (!CryptBinaryToString(
		pbData,
		dwDataLen,
		CRYPT_STRING_BASE64,
		NULL,
		&bufflen)) {
		LOG((1,"decryptString: Error calculating base64 length"));
		goto cleanup;
	}
	LOG((5,"encryptString: CryptBinaryToString1 succeeded"));

	if ( !(buff = (LPTSTR) LocalAlloc(LPTR, bufflen*sizeof(TCHAR))) ) {
		LOG((1,"decryptString: error allocating %d bytes for base64 encoding", bufflen*sizeof(TCHAR) ));
		goto cleanup;
	}

	// 2. encode with base64
	if (!CryptBinaryToString(
		pbData,
		dwDataLen,
		CRYPT_STRING_BASE64,
		buff,
		&bufflen)) {
		LOG((1,"decryptString: Error converting to base64"));
		if (buff) {
			LocalFree(buff);
			buff = NULL;
		}
		goto cleanup;
	}
	LOG((5,"encryptString: CryptBinaryToString2 succeeded"));

cleanup:
	if (pbData) LocalFree(pbData);
	if (hProv) CryptReleaseContext(hProv, 0);
	return buff;
}
