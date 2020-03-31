# ProcessBouncerService
A process-based malware protection tool.

## Setup:
* Open: cmd as admin
* Enter: `sc create "ProcessBouncerService" binPath="<PathToExe>"` or `C:\Windows\Microsoft.NET\Framework\v<newest>\installutil.exe "<PathToExe>"`
* Open: Control Panel > Administrative Tools > Services and start ProcessBouncerService
* Create: "C:\ProcessBouncer\"
* Move: config.txt and sig into "C:\ProcessBouncer\"

## Config:
Comments start with a `#` and will be ignored. Please don't add new lines or spaces in the listings. More comfortable way will be added in the future.