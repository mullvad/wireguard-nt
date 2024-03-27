@echo off

if [%VisualStudioVersion%]==[] (
  echo Please launch this build script from a Visual Studio command prompt
  exit /b 1
)

if [%1]==[] goto USAGE
if [%2]==[] goto USAGE

set CERT_THUMBPRINT=%1
set CROSSCERT=%2
set TIMESTAMP_SERVER=http://timestamp.digicert.com

set ROOT=%~dp0

rmdir /s /q %ROOT%Release

msbuild.exe %ROOT%driver\driver.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Sign driver

signtool sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 "%1" /v /ac %ROOT%%CROSSCERT% %ROOT%Release\amd64\driver\mullvad-wireguard.sys

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Re-generate catalog file now that driver binary has changed

del %ROOT%Release\amd64\driver\mullvad-wireguard.cat
"%WindowsSdkVerBinPath%x86\inf2cat.exe" /driver:%ROOT%Release\amd64\driver /os:"10_x64" /verbose

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Sign catalog

signtool sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 "%1" /v /ac %ROOT%%CROSSCERT% %ROOT%Release\amd64\driver\mullvad-wireguard.cat

IF %ERRORLEVEL% NEQ 0 goto ERROR

:: Copy artifacts

rmdir /s /q %ROOT%bin\dist
mkdir %ROOT%bin\dist
copy /b %ROOT%Release\amd64\driver\* %ROOT%bin\dist\

::
:: Build a CAB file for submission to the MS Hardware Dev Center
::

pushd %ROOT%bin\dist\win10
makecab /f "%ROOT%mullvad-wireguard.ddf"
popd

IF %ERRORLEVEL% NEQ 0 goto ERROR

signtool sign /tr %TIMESTAMP_SERVER% /td sha256 /fd sha256 /sha1 "%1" /v /ac %ROOT%%CROSSCERT% %ROOT%bin\dist\win10\mullvad-wireguard.cab

IF %ERRORLEVEL% NEQ 0 goto ERROR

echo;
echo BUILD COMPLETED SUCCESSFULLY
echo;

exit /b 0

:USAGE

echo Usage: %0 ^<cert_sha1_hash^> ^<cert_root_ca_path^>
exit /b 1

:ERROR

echo;
echo !!! BUILD FAILED !!!
echo;

exit /b 1
