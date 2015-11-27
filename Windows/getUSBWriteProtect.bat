@ECHO OFF &SETLOCAL
:: ****************
::
:: 			getUSBProtect v.01
::
:: @Fecha:		16/09/2015
:: @Version:	0.1
:: @Autor: 		Julian J. Gonzalez
:: @Dept:		ST2Labs / www.seguridadparatodos.es
::
:: ****************

SET key="HKLM\System\CurrentControlSet\Control\StorageDevicePolicies"
SET value=WriteProtect

:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"
:--------------------------------------

:: Check if Key exist
reg query %key% >nul 2>&1
IF ERRORLEVEL 1 (
	GOTO writeup
)

:: Key exist and now we can verify Registry Value
FOR /F "tokens=2*" %%A IN ('reg query %key% /v %value%') DO SET _base=%%B

:: Verify is WriteProtect is Enable
if %_base%==0x1 (
	GOTO writeoff
) else ( GOTO writeup )

:writeup	
reg add %key% /v %value% /t REG_DWORD /d 0x1 /f
mshta "about:<script>alert('USB Write Protect is Enable !!!');close()</script>"
GOTO:EOF

:writeoff
reg add %key% /v %value% /t REG_DWORD /d 0x0 /f
mshta "about:<script>alert('USB Write Protect is Disable !!!');close()</script>"
GOTO:EOF
