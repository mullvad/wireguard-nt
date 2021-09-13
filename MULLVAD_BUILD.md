# Prerequisites

* `Visual Studio 2019`
* `Windows Driver Kit (WDK)`

# Preparation

Configure signing locally:

1. Install `Safenet Authentication Client`.
1. Register EV certificate in user store.

Configure signing in Microsoft partner portal:

1. Partner portal login page (use Azure account): [Partner Portal](https://partner.microsoft.com/en-us/dashboard/hardware)
1. Instructions for registering EV certificate with Microsoft: [Add or Update a code signing certificate](https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/update-a-code-signing-certificate)
1. Instructions for configuring attestation signing: [Attestation signing a kernel driver for public release](https://docs.microsoft.com/en-us/windows-hardware/drivers/dashboard/attestation-signing-a-kernel-driver-for-public-release)

# Building and signing the driver

1. Clone/pull updated driver code on trusted build machine.
1. Launch `Developer Command Prompt for VS 2019`.
1. Run `build.bat <certificate-sha1-thumbprint>` to build and sign the driver.
1. Ensure that the final, signed artifacts for Windows 7/8/8.1 were produced in `bin/dist/`, and a driver package CAB file in `bin/dist/win10`.
1. Upload Windows 10 driver package (`mullvad-wireguard.cab`) to Microsoft for attestation signing.
1. Download and extract the attestation signed driver and related files to `bin/dist/win10`.

# Building mullvad-wireguard.dll

1. Launch `Developer Command Prompt for VS 2019`.
1. Build the relevant projects:
    1. Build `downlevelshim`: `msbuild.exe downlevelshim\downlevelshim.vcxproj /p:Configuration=Release /p:Platform=x64`
    1. Build `api`: `msbuild.exe api\api.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off`
1. To sign `mullvad-wireguard.dll`, replace `<certificate-sha1-thumbprint>` below and run:
    signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /sha1 "<certificate-sha1-thumbprint>" /v /ac digicert-high-assurance-ev.crt Release\amd64\mullvad-wireguard.dll
1. Copy `Release\amd64\mullvad-wireguard.dll` to `bin/dist/`.

## Windows 10

1. Open `api\\resources.rc`.
1. Replace all strings `..\\..\\bin\\dist\\` with `..\\..\\bin\\dist\\win10\\`.
1. Repeat steps 1-3 under `Building mullvad-wireguard.dll`.
1. Copy `Release\amd64\mullvad-wireguard.dll` to `bin/dist/win10/`.