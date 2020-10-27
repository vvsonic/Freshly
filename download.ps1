Set-ExecutionPolicy Bypass
function downloadbuilder {
Invoke-WebRequest -Uri "https://github.com/vvsonic/Freshly/archive/main.zip" -OutFile "C:\Freshly\Freshly.zip"
Expand-Archive C:\Freshly\Freshly.zip -DestinationPath C:\Freshly\
}
downloadbuilder