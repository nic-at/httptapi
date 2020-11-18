# HTTPTAPI

HTTPTAPI is a TAPI Service Provider for Windows. It basically only implements the TSPILineMakeCall function and generates HTTP(S) request(s). This can be used to initiate calls using web services of PBX or using the buit-in webserver of SIP phones.

HTTPTAPI was a commercial product of ipcom GmbH - see README.docx.

## Getting Started

To compile the code you need to link against libcurl and libssl. HTTPTAPI was a commerical product which required a license. You might want to remove this part of the code.

### Prerequisites

Compile libcurl and libssl.

### Installing

Once compiled, copy the .tsp file into the Windows\system32 directory. Copy the file using the Windows Explorer to avoid SysWOW64 issues.

### License Key

The latest release binaries still contains the license check. You can use this 9999 lines license (just enter it in the Configuration->LicenseInfo window and press "apply"):

CE3rCZyNoZykP57K0x0mRgCkIz9vr17CgxpPM2OfAT8USBDAZthYuoNsiRxnYF2v8m882F
cY+DunOuk/Hu9kOGCQ+hzEolsM
