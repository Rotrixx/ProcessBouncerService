@echo off
set target=%~dp0%ProcessBouncer
xcopy "%target%" "C:\ProcessBouncer\"
sc create "ProcessBouncerService" binPath="C:\ProcessBouncer\ProcessBouncerService.exe"
sc config "ProcessBouncerService" start=auto
sc start "ProcessBouncerService"