# ProcessBouncerService
A process-based malware protection tool.

ProcessBouncerService is based on the Powershellscript ProcessBouncer (https://github.com/hjunker/ProcessBouncer) but implemented as an Windows Service. It uses WMI to get information of newly created processes. If a process is suspicious it will be terminated or the user chooses what to do with the suspicious process.

## Setup:
* Download and extract
* Run Install.ps1 as admin

## Configuration:
Comments start with a `#` and will be ignored. Please don't add new lines or spaces in the listings.

If you want to add your own signatures, add the MD5-Hashes in a file with each hash on a new line to `C:\ProcessBouncer\signatures\`. Currently there are 421803 Hashes from ClamAV Virus Database (https://www.clamav.net/downloads) in `C:\ProcessBouncer\signatures\sig`.

ProcessBouncerService does also support dynamic signatures(Hex-strings). **This is in a early testing stage.**

## **NOTES:**
The service dosen't start automatically and may cause problems if started too early(during startup).
The GUI has to be started before the service or the popup's dont work correctly.
This project is currently work in progress. Only basic functionality is working right now. Suggestions and feedback is more than welcome.

## Contact:
If you have questions, feedback or suggestions feel free to contact me.

Twitter: [@r0trixx](https://mobile.twitter.com/r0trixx/)
