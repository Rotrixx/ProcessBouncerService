Enable-WindowsOptionalFeature -Online -FeatureName MSMQ-Server

New-MsmqQueue -Name "pbq" -QueueType Private
Get-MsmqQueue -Name "pbq" -QueueType Private | Set-MsmqQueueAcl -UserName "Everyone" -Allow Receive
Get-MsmqQueue -Name "pbq" -QueueType Private | Set-MsmqQueueAcl -UserName "Everyone" -Allow Send

Copy-Item '.\ProcessBouncer\' -Destination 'C:\ProcessBouncer' -recurse

New-Service -Name "ProcessBouncerService" -BinaryPathName "C:\ProcessBouncer\ProcessBouncerService.exe" -StartupType "Manual" -Description "A process-based malware protection tool."

Start-Process -FilePath "C:\ProcessBouncer\ProcessBouncerGUI.exe"

Write-Host -NoNewLine 'Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');