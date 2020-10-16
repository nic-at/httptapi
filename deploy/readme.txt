Installation of HTTPTAPI
------------------------

On 32bit Windows
=================
1. Copy httptapi.tsp from x86 folder into your Windows system32 directory 
   (usually C:\Windows\System32)
2. Install and configure HTTPTAPI using the telephony options from control panel:
   -> Control Panel -> Phone and Modem Options -> Advanced -> Add -> HTTPTAPI

On 64bit Windows
=================
1. Copy httptapi.tsp from x64 folder into your Windows system32 directory 
   (usually C:\Windows\System32). This gives you full TAPI support with 64 and 32bit
   TAPI applications
   Note: You MUST copy the httptapi.tsp file with a 64bit application. If you use a 32bit
   application, Windows will transparently map the system32 folder to SysWOW64 (32bit 
   compatibility for 64bit Windows). Therefore, the following method is preferred:
   1. Unzip the httptapi.tsp file on your Desktop
   2. Use Windows-Explorer to move the httptapi.tsp file from your Desktop to c:\Windows\system32
2. Install and configure HTTPTAPI using the telephony options from control panel:
   -> Control Panel -> Phone and Modem Options -> Advanced -> Add -> HTTPTAPI

Notes
=================
Installation and configuration requires Administrator privileges. Configuration must be done
via Control Panel -> Phone and Modem Options. Configuration from the dial dialog of the TAPI
application will fail (you can safely ignore the error messages and the empty configuration dialog).

