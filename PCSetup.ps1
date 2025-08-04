Set-ExecutionPolicy -ExecutionPolicy Bypass

# Begin by creating the various functions which will be called at the end of the script. You can create additional functions if needed.
function SetPCName {
    # In our MSP we designate all systems in the format assetid-companyname for example 288111-SS
   
    Add-Type -AssemblyName Microsoft.VisualBasic
    $rename= [Microsoft.VisualBasic.Interaction]::MsgBox('Do you want to Rename this PC?', 'YesNo,Information' , 'Rename This PC?') 
    if ($rename -match "Yes")
    { 
        $SystemID = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a System ID #')
        $CompanyName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter Company Name, Abbreviation', 'Company Initials')
        Write-Output "This computer will be renamed $SystemID-$CompanyName"
        Rename-Computer -NewName "$SystemID-$CompanyName"
    } 
    else 
    {
    Write-Output "This PC will not be renamed at this time"
    }
}

function InstallChoco {
    # Ask for elevated permissions if required
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
        }
    # Install Chocolatey to allow automated installation of packages  
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }

function InstallApps {
    # Install the first set of applications. these are quick so ive added them separately
    choco upgrade microsoft-edge googlechrome firefox 7zip.install notepadplusplus.install adobereader dotnet3.5 --install-if-not-installed -y
    # Install Office365 applications. This takes a while so is done separately. You can change the options here by following the instructions here: https://chocolatey.org/packages/microsoft-office-deployment
    choco install microsoft-office-deployment --params="'/Channel:Monthly /Language:en-us /64bit /Product:O365BusinessRetail /Exclude:Lync,Groove'" -y
    #choco upgrade microsoft-office-deployment --params="'/Channel:Monthly /Language:en-us /Product:O365BusinessRetail /Exclude:Lync,Groove'" -y 
}

function ReclaimWindows
{
    ##########
    # Service Tweaks
    ##########

    # Enable Windows Defender
    Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware"

    # Disable Windows Update automatic restart
    Write-Host "Disabling Windows Update automatic restart..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1

    # Disable Remote Desktop
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1

    ##########
    # UI Tweaks
    ##########

    # Disable Action Center
    #Write-Host "Disabling Action Center..."
    #If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer")) {
    #  New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
    #}
    #Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    #Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0

    # Disable Autoplay
    Write-Host "Disabling Autoplay..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

    # Disable Autorun for all drives
     Write-Host "Disabling Autorun for all drives..."
     If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
       New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
     Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

   
    #Disable Sticky keys prompt
    Write-Host "Disabling Sticky keys prompt..."
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"

  

    # Hide Task View button
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

    # Show known file extensions
    Write-Host "Showing known file extensions..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

   # Change default Explorer view to "Computer"
    Write-Host "Changing default Explorer view to `"Computer`"..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

    # Show Computer shortcut on desktop
    Write-Host "Showing Computer shortcut on desktop..."
    If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0


  # Show Photo Viewer in "Open with..."
    Write-Host "Showing Photo Viewer in `"Open with...`""
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
    New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
    Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"

    ####################
    ## Win 11 Tweaks ###
    ####################
    
    ## Customise Taskbar
    
    # Set the chat icon to be hidden
    Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "TaskbarMn" -Value 0
    
    # Set the widget icon to be hidden
    Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "TaskbarDa" -Value 0
    
    # Set the task view icon to be hidden
    #Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "ShowTaskViewButton" -Value 0
    
    # Moves the Taskbar to left
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $Al = "TaskbarAl" # Shifts Start Menu Left
    $value = "0"
    New-ItemProperty -Path $registryPath -Name $Al -Value $value -PropertyType DWORD -Force -ErrorAction Ignore
    
    
    ## Uninstall consumer Teams app
    
    $installedApps = Get-AppxPackage
    
    if ($installedApps -eq $null) {
        Write-Output "No apps are installed on the system."
    }
    else {
        $teamsApp = $installedApps | Where-Object {$_.Name -eq "MicrosoftTeams"}
    
        if ($teamsApp -eq $null) {
            Write-Output "The Microsoft Teams app is not installed on the system."
        }
        else {
            Remove-AppxPackage -Package $teamsApp.PackageFullName
        }
    }
    
    
    ## Remove Win11 right-click menu
    
    New-Item -Path HKCU:\Software\Classes\CLSID -Name "{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -ItemType "Key"
    New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -ItemType "Key"
    Set-ItemProperty "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(Default)" -Value ""


}

function DebloatWindows
#{curl -L cleanup.umbrellaitgroup.com -o cleanup.cmd && cleanup.cmd}
{ cmd.exe /c C:\Freshly\Freshly-main\debloat.bat}
   
# Uploads a default layout to all NEW users that log into the system. Effects task bar and start menu
function LayoutDesign {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }
    Import-StartLayout -LayoutPath "C:\Freshly\Freshly-main\LayoutModification.xml" -MountPath $env:SystemDrive\
    }
    
function ApplyDefaultApps {
    dism /online /Import-DefaultAppAssociations:C:\Freshly\Freshly-main\AppAssociations.xml
}

function AutomateShortcut {
    #Creates Desktop Shortcut to Automate Login Page#
    param(
        [string]$ShortcutName         = "Download Sonic Agent",
        [string]$ShortcutUrl          = "https://automate.vvsonic.com/automate/",
        [string]$ShortcutIconLocation = "https://automate.vvsonic.com/automate/favicon.ico",
        [bool]$ShortcutOnDesktop      = $true,
        [bool]$ShortcutInStartMenu    = $true
    )
    
    $WScriptShell = New-Object -ComObject WScript.Shell
    
    if ($ShortcutOnDesktop) {
        $Shortcut = $WScriptShell.CreateShortcut("$env:USERPROFILE\Desktop\$ShortcutName.lnk") 
        $Shortcut.TargetPath = $ShortcutUrl
        if ($ShortcutIconLocation) {
            $Shortcut.IconLocation = $ShortcutIconLocation
        }
        $Shortcut.Save()
    }
    
    if ($ShortCutInStartMenu) {
        $Shortcut = $WScriptShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\$ShortcutName.lnk") 
        $Shortcut.TargetPath = $ShortcutUrl 
        if ($ShortcutIconLocation) {
            $Shortcut.IconLocation = $ShortcutIconLocation
        }
        $Shortcut.Save()
    }
    
    
}

# Start and Install Windows Updates
function WindowsUpdates 
{
    If (-not(Get-PackageProvider PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Install-PackageProvider NuGet -Confirm:$False -Force
    }

    If (-not(Get-InstalledModule PSWindowsUpdate -ErrorAction silentlycontinue)) {
        Install-Module PSWindowsUpdate -Confirm:$False -Force
    }

    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File C:\Temp\PSWindowsUpdate.log
}

# Custom power profile used for our customers. Ensures systems do not go to sleep.
function SonicPower {
    POWERCFG -DUPLICATESCHEME 381b4222-f694-41f0-9685-ff5bb260df2e 381b4222-f694-41f0-9685-ff5bb260aaaa
    POWERCFG -CHANGENAME 381b4222-f694-41f0-9685-ff5bb260aaaa "Sonic Systems Power Management"
    POWERCFG -SETACTIVE 381b4222-f694-41f0-9685-ff5bb260aaaa
    POWERCFG -Change -monitor-timeout-ac 15
    POWERCFG -CHANGE -monitor-timeout-dc 5
    POWERCFG -CHANGE -disk-timeout-ac 30
    POWERCFG -CHANGE -disk-timeout-dc 5
    POWERCFG -CHANGE -standby-timeout-ac 0
    POWERCFG -CHANGE -standby-timeout-dc 30
    POWERCFG -Hibernate off
    Remove-Item "C:\hiberfil.sys" -Force
    
}

function SonicLocalAdmin{
###Create Sonic Support User and add as Local Admin###
$securepwdfilepath = 'C:\Freshly\Freshly-main\Cred\pass.file'
$AESKeyFilePath = 'C:\Freshly\Freshly-main\Cred\keys.txt'
$AESKeyFile = Get-Content $AESKeyFilePath
$pwdtxt = Get-Content $securepwdfilepath
$passwd = $pwdtxt | ConvertTo-SecureString -Key $AESKeyFile
$user = "Sonic"
#Check if User Exists Already
$op = Get-LocalUSer | where-Object Name -eq "sonic" | Measure
if ($op.Count -eq 0) {
     #Create User and Add to Local Admin Group
     New-LocalUser $user -Password $passwd
     Add-LocalGroupMember -Group "Administrators" -Member $user

} else {
     # Reset Password for User to new Password
     Set-LocalUser -Name $user -Password $passwd
    }

}

function RestartPC{
    #Prompts if reboot is needed or not, if no will display message then end setup script#
    
    $reboot= [Microsoft.VisualBasic.Interaction]::MsgBox('Do  you want to Reboot the PC?' , 'YesNo,Information' , 'Reboot')
    if ($reboot -match "Yes")
    { 
      Restart-Computer  
    } 
    else 
    {
    Write-Output "Reboot has been canceled. Please reboot at your convenivce to complete the setup"
    }
}


InstallChoco
InstallApps
DebloatWindows
ReclaimWindows
LayoutDesign
ApplyDefaultApps
WindowsUpdates
AutomateShortcut
SonicPower
SonicLocalAdmin
SetPCName
RestartPC
