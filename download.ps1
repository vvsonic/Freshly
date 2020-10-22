Set-ExecutionPolicy Bypass
function downloadbuilder {
Invoke-WebRequest -Uri "https://github.com/vvsonic/Freshly/archive/main.zip" -OutFile "C:\Freshly\PCdeploy.zip"
Expand-Archive C:\Freshly\PCdeploy.zip -DestinationPath C:\Freshly\
}
downloadbuilder