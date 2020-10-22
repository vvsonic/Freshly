REM Create a directory on the C drive to store the scripts from the repository
mkdir c:\Freshly
REM Disabling UAC for allowing the following scripts to complete
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
REM Enable execution policy to allow running of scripts
Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList 'set-executionpolicy remotesigned' -Verb RunAs}"
REM Download the most up to date version of the script from the repository. download.ps1 must be in the same directory as RunMe.bat
Powershell.exe -command "&{start-process powershell -ArgumentList '-noprofile -file \"%~dp0download.ps1\"' -verb RunAs}"
REM The download.ps1 auto extracts the contents to c:\Freshly. Wait 10 seconds for this to complete before executing the PCSetup.ps1 script
timeout 10
REM Execute the final build script
powershell.exe -command "&{start-process powershell -ArgumentList '-noprofile -file \"C:\Freshly\Freshly-main\PCSetup.ps1\"' -verb RunAs}"
