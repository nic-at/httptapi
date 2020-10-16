/*++

Copyright 2009-2012 IPcom GmbH
Copyright 1995 - 2000 Microsoft Corporation

Module Name:

    ExportCertificates.h

These functions dump the CA certificates from the Windows 
certificate store into the file provided by the file handle

--*/

#pragma once

// We are using "insecure" string functions. But this 
// shouldn't be a problem, as we carefully check the number of characters
// and null-terminate them always!
#pragma warning (disable:4996)

/*
 * generate an absolute filename pointing to the user's temp directory
 *
 * filename: generated name of the absolute filename (with terminating 0) will 
 *           be stored in this buffer
 * len: length of buffer
 * suffix: name of the file in the temp directory
 * 
 * return value: 0 == OK, other values indicate error
 *
 * Note that the function does not verify that the path exists, nor 
 * does it test to see if the current process has any kind of access
 * rights to the path. 
 *
 */
int getTemporaryFilename(char *filename, size_t len, const char* suffix);

/*
 * generates(overwrites) a file and export certificates into this file
 *
 * filename: file which should be created
 *
 * return value: 0 == OK, other values indicate error
 */
int exportCertificates(const char* filename);

/*
 * export certificates 
 *
 * h: the already opened file handle
 * 
 * return value: 0 == OK, other values indicate error
 */
int ExportCertificatesToFile(HANDLE h);

/*
 * export certificates 
 *
 * binary: binary data which should be encoded
 * len: length of binary data
 * 
 * return value: pointer to a allocated buffer with the base64 string, NULL on errors
 *
 * NOTE: the returned buffer must be freed with LocalFree().
 */
char * base64_Encode(BYTE const* binary, DWORD len);

