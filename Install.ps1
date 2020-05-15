Enable-WindowsOptionalFeature -Online -FeatureName "MSMQ-Server" -all

New-MsmqQueue -Name "pbq" -QueueType Private
$lang = [System.Globalization.Cultureinfo]::CurrentCulture.Name
If ($lang -match "de-"){
	Get-MsmqQueue -Name "pbq" -QueueType Private | Set-MsmqQueueAcl -UserName "Jeder" -Allow ReceiveMessage
	Get-MsmqQueue -Name "pbq" -QueueType Private | Set-MsmqQueueAcl -UserName "Jeder" -Allow WriteMessage
}
ElseIf ($lang -match "en-"){
	Get-MsmqQueue -Name "pbq" -QueueType Private | Set-MsmqQueueAcl -UserName "Everyone" -Allow ReceiveMessage
	Get-MsmqQueue -Name "pbq" -QueueType Private | Set-MsmqQueueAcl -UserName "Everyone" -Allow WriteMessage
}
Else{
	Write-Host "Please edit this script to support your language"
}

Copy-Item '.\ProcessBouncer\' -Destination 'C:\ProcessBouncer' -recurse

Write-Host "Do you want to start service:"
Write-Host "1 - automatically without gui (recommended)"
Write-Host "2 - automatically with gui"
Write-Host "3 - manually"
$instType = Read-Host

If ($instType -eq 1){
	New-Service -Name "ProcessBouncerService" -BinaryPathName "C:\ProcessBouncer\ProcessBouncerService.exe" -StartupType "Automatic" -Description "A process-based malware protection tool."
}ElseIf ($instType -eq 2){
	New-Service -Name "ProcessBouncerService" -BinaryPathName "C:\ProcessBouncer\ProcessBouncerService.exe" -StartupType "Automatic" -Description "A process-based malware protection tool."
	Copy-Item "C:\ProcessBouncer\ProcessBouncerGUI.exe" -Destination "C:\Users\$env:UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\ProcessBouncerGUI.exe"
	Write-Host "Please add C:\Users\[Your Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup to the whitelisted Path in the config file."
}ElseIf ($instType -eq 3){
	New-Service -Name "ProcessBouncerService" -BinaryPathName "C:\ProcessBouncer\ProcessBouncerService.exe" -StartupType "Manual" -Description "A process-based malware protection tool."
}Else{
	Write-Host "Please select 1 2 or 3"
}

Start-Process -FilePath "C:\ProcessBouncer\ProcessBouncerGUI.exe"