REM Execute the settings script
powershell.exe -command "&{start-process powershell -ArgumentList '-noprofile -file \"C:\ProgramData\Freshly\SonicSettings.ps1"' -verb RunAs}"
