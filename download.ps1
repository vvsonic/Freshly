Set-ExecutionPolicy Bypass
$FileName1 = "C:\Freshly\Freshly.Zip"
$FileName2 = "C:\Freshly\Freshly-main"
    If ((test-path $FileName1) -and (test-path $FileName2))
    {
      Remove-Item $FileName1 -Force
      Remove-Item $FileName2 -Force    
    }

function downloadbuilder {

     Invoke-WebRequest -Uri "https://github.com/vvsonic/Freshly/archive/main.zip" -OutFile "C:\Freshly\Freshly.zip"
     Expand-Archive C:\Freshly\Freshly.zip -DestinationPath C:\Freshly\
}
downloadbuilder