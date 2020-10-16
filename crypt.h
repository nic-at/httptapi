/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name: crypt.h

Simple de-/encryption functions, e.g. to store passwords encrypted in the registry

--*/

#pragma once

// DesKeyBlob:      A plaintext key BLOB stored in a byte array. The 
//                  byte array  must have the following format:
//                      BLOBHEADER hdr;
//                      DWORD dwKeySize;
//                      BYTE rgbKeyData [];

// Our DES Key with Parity
// 6e d3 86 79 94 04 6d c2
BYTE SimpleDesKeyBlob[] = {
    0x08,0x02,0x00,0x00,0x01,0x66,0x00,0x00, // BLOB header 
    0x08,0x00,0x00,0x00,                     // key length, in bytes
    0x6e,0xd3,0x86,0x79,0x94,0x04,0x6d,0xc2  // DES key with parity
};


/*
 * accepts a base64 encoded, DES-encrypted string and returns
 * the plain text
 *
 * szencryptedString: 0 terminated base64 string
 *
 * return value: pointer to an allocated buffer with the plain text,
 *               NULL in case of error
 *
 * Note: the returned buffer must be freed with LocalFree()
 */
char* decryptString(const char *szencryptedString);

/*
 * accepts a plain text string and returns a DES-encrypted string 
 * in base64 format
 *
 * szplainString: 0 terminated plain text
 *
 * return value: pointer to an allocated buffer with the encrypted text in base64 format,
 *               NULL in case of error
 *
 * Note: the returned buffer must be freed with LocalFree()
 */
char* encryptString(const char *szplainString);
