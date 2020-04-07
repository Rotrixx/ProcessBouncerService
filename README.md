# ProcessBouncerService
A process-based malware protection tool.

ProcessBouncerService is based on the Powershellscript ProcessBouncer (https://github.com/hjunker/ProcessBouncer) but implemented as an Windows Service. It uses WMI to get information of newly created processes. If a process is suspicious it will be terminated or the user chooses what to do with the suspicious process (will be added soon).

## Setup:
* Download and extract
* Run Install.bat as admin

## Configuration:
Comments start with a `#` and will be ignored. Please don't add new lines or spaces in the listings. More comfortable and secure way will be added in the future.

If you want to add your own signatures, add the MD5-Hash in a new line to `C:\ProcessBouncer\sig`. Currently there are 421803 Hashes from ClamAV Virus Database (https://www.clamav.net/downloads) in `C:\ProcessBouncer\sig`.

## Contact:
If you have questions, feedback or suggestions feel free to contact me.

Twitter: @r0trixx