Enable-WindowsOptionalFeature -Online -FeatureName MSMQ-Server

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
	WriteHost "Please edit this script to support your language"
}

Copy-Item '.\ProcessBouncer\' -Destination 'C:\ProcessBouncer' -recurse

New-Service -Name "ProcessBouncerService" -BinaryPathName "C:\ProcessBouncer\ProcessBouncerService.exe" -StartupType "Manual" -Description "A process-based malware protection tool."

Start-Process -FilePath "C:\ProcessBouncer\ProcessBouncerGUI.exe"