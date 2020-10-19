Start-Process Powershell -Verb runAs
Set-ExecutionPolicy remotesigned
function downloadbuilder {
Invoke-WebRequest -Uri "http://sc1.soniccloud.org/portal/s/0148648199101696450934.zip" -OutFile "C:\Freshly\PCdeploy.zip"
Expand-Archive C:\Freshly\PCdeploy.zip -DestinationPath C:\Freshly\
}
downloadbuilder