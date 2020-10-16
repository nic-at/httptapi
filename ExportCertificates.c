/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation
Copyright 2007 Cong Zhang <ftofficer.zhangc@gmail.com>

Module Name:

ExportCertificates.c

These functions dump the CA certificates from the Windows 
certificate store into the file provided by the file handle

--*/

#include <windows.h>
#include <Wincrypt.h>
#include <stdio.h>

#include "ExportCertificates.h"
#include "tapi_logging.h"

enum OutputType
{
	Cert_Type_Unknown,
	Cert_Type_Certificate,
	Cert_Type_PKCS7,
	Cert_Type_X509CRL
};

char const* GetTypeName(enum OutputType type)
{
	switch (type)
	{
	case Cert_Type_Certificate:
		return "CERTIFICATE";
	case Cert_Type_PKCS7:
		return "PKCS7";
	case Cert_Type_X509CRL:
		return "X509 CRL";
	case Cert_Type_Unknown:
		return NULL;
	default:
		break;
	}

	return NULL;
}

int IsPKCS7(DWORD encodeType)
{
	return ((encodeType & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING);
}


int AppendToFile(HANDLE h, char *data, int len) {
	DWORD writecount;

	WriteFile(h, data, len, &writecount, 0);
	if (writecount != len) {
		LOG((1,"AppendToFile: Error, wrote only %d from &d bytes", writecount, len));
		return 1;
	}
	return 0;
}


int WritePEM(HANDLE h, enum OutputType outputType, BYTE const* pData, DWORD cbLength) {
	char buffer[50000];
	char *base64;
	int len;
	char const* type = GetTypeName(outputType);
	if ( type == NULL ) return 0;

	base64 = base64_Encode(pData, cbLength);
	if (base64 == NULL  ) {
		LOG((1,"WritePEM: Error getting certificate in base64"));
		return 1;
	}

	LOG((1,"WritePEM: Exporting certificate type: %s", type));
	len = _snprintf(buffer, sizeof(buffer)-1, "%s%s%s\r\n%s%s%s%s\r\n\r\n", 
		"-----BEGIN ", type, "-----", 
		base64,
		"-----END ", type, "-----");

	if (base64) LocalFree(base64);

	if (len < 0) {
		LOG((1,"WritePEM: Buffer too small"));
		return 1;
	}
	return(AppendToFile(h,buffer,len));
}

int ExportCertificatesToFile(HANDLE h) {
	PCCERT_CONTEXT pCertCtx;
	PCCRL_CONTEXT pCrlCtx;
	enum OutputType outputType;
	HCERTSTORE hStore;
	FILETIME now;

	LOG((5,"ExportCertificatesToFile: Begin export ..."));

	hStore = CertOpenSystemStore((HCRYPTPROV_LEGACY) NULL, "ROOT");

	if (hStore == NULL) {
		LOG((1,"ExportCertificatesToFile: Error CertOpenSystemStore(CA)"));
		return 1;
	}

	GetSystemTimeAsFileTime(&now);

	for ( pCertCtx = CertEnumCertificatesInStore(hStore, NULL);
		pCertCtx != NULL;
		pCertCtx = CertEnumCertificatesInStore(hStore, pCertCtx) ) {
			LOG((5,"ExportCertificatesToFile: Exporting a certificate from Certificate store ...)"));
			if (CompareFileTime(&(pCertCtx->pCertInfo->NotAfter), &now) != 1) {
				LOG((3,"ExportCertificatesToFile: This certificate is already expired, ignore ...)"));
				continue;
			}
			outputType = IsPKCS7(pCertCtx->dwCertEncodingType) ? Cert_Type_PKCS7 :	Cert_Type_Certificate;
			WritePEM(h, outputType, pCertCtx->pbCertEncoded, pCertCtx->cbCertEncoded);
	}

	for ( pCrlCtx = CertEnumCRLsInStore(hStore, NULL);
		pCrlCtx != NULL;
		pCrlCtx = CertEnumCRLsInStore(hStore, pCrlCtx) ) {
			LOG((5,"ExportCertificatesToFile: Exporting a certificate from CLR store ...)"));
			outputType = IsPKCS7(pCrlCtx->dwCertEncodingType) ? Cert_Type_PKCS7 : Cert_Type_X509CRL;
			WritePEM(h, outputType, pCrlCtx->pbCrlEncoded, pCrlCtx->cbCrlEncoded);
	}

	LOG((5,"ExportCertificatesToFile: Begin export ... done"));

	CertCloseStore(hStore, 0);
	return 0;
}

char * base64_Encode(BYTE const* binary, DWORD len) {
	DWORD bufflen;
	char *buff;

	CryptBinaryToString(
		binary,
		len,
		CRYPT_STRING_BASE64,
		0,
		&bufflen);

	LOG((5,"base64_Encode: need to allocate %ld elements ...",bufflen));

	if ( !(buff = (char *) LocalAlloc (LPTR, bufflen*sizeof(BYTE) + 1)) ) {
		LOG((1,"base64_Encode: Failed to allocate %ld bytes ...",bufflen*sizeof(BYTE) + 1));
		return NULL;
	}

	if ( CryptBinaryToString(
			binary,
			len,
			CRYPT_STRING_BASE64,
			(BYTE *) buff,
			&bufflen) == 0 ) {
		LOG((1,"base64_Encode: CryptBinaryToString failed"));
		LocalFree(buff);
		return NULL;
	}

	LOG((5,"base64_Encode: Encoding needed %ld bytes ...",bufflen));

	return buff;
}

int getTemporaryFilename(char *filename, size_t len, const char* suffix) {
	// Note that the function does not verify that the path exists, nor 
	// does it test to see if the current process has any kind of access
	// rights to the path. 
	// A pointer to a string buffer that receives the null-terminated string 
	// specifying the temporary file path. The returned string ends with 
	// a backslash, for example, "C:\TEMP\".
	CHAR temp[MAX_PATH];
	DWORD dwRetVal = 0;
	int i;
	dwRetVal = GetTempPath(sizeof(temp), temp);
	if (dwRetVal > sizeof(temp) || (dwRetVal == 0)) {
		LOG((1,"getTemporaryFilename: GetTempPath failed with 0x%08x", GetLastError()));
		return 1;
	}
	LOG((3,"GetTempPath returned %s", temp));
	i = _snprintf(filename, len, "%s%s", temp, suffix);
	if (i < 0 ) {
		LOG((1,"getTemporaryFilename: not enough space in buffer to generate filename"));
		return 2;
	}
	LOG((3,"getTemporaryFilename: complete file name is %s", filename));
	return 0;
}

int exportCertificates(const char* filename) {
	HANDLE hTempFile = INVALID_HANDLE_VALUE;
	int fSuccess;
	DWORD dwBytesWritten = 0; 

	LOG((5,"exportCertificates: START"));

	//  Creates the new file to export the CAs
    hTempFile = CreateFile((LPTSTR) filename, // file name 
                           GENERIC_WRITE,        // open for write 
                           0,                    // do not share 
                           NULL,                 // default security 
                           CREATE_ALWAYS,        // overwrite existing
                           FILE_ATTRIBUTE_NORMAL,// normal file 
                           NULL);                // no template 
    if (hTempFile == INVALID_HANDLE_VALUE) { 
		LOG((1,"exportCertificates: CreateFile %s failed with 0x%08x", 
			filename, GetLastError()));
		return 1;
	} else {
		LOG((5,"exportCertificates: File %s created", filename));
	}

	fSuccess = ExportCertificatesToFile(hTempFile);
	if (fSuccess) {
		LOG((1,"exportCertificates: ExportCertificates to %s failed with return value %d",
			filename, fSuccess));
		CloseHandle(hTempFile);
		return 2;
	} else {
		LOG((5,"exportCertificates: Exported certificates to file %s", filename));
	}
	
	if (!CloseHandle(hTempFile)) {
		LOG((1,"exportCertificates: CloseHandle for file %s failed with 0x%08x", 
			filename, GetLastError()));
		return 3;
	} else {
		LOG((5,"exportCertificates: Closed file %s", filename));
	}
	LOG((5,"exportCertificates: STOP"));
	return 0;
}
