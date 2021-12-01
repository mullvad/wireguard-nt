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

# Building and signing mullvad-wireguard.dll

1. Clone/pull updated driver code on trusted build machine.
1. Launch `Developer Command Prompt for VS 2019`.
1. Run `build.bat <certificate-sha1-thumbprint>` to build and sign the driver.
1. Upload Windows 10 driver package (`bin/dist/win10/mullvad-wireguard.cab`) to Microsoft for attestation signing.
1. Download and extract the attestation signed driver and related files to `bin/dist/win10`.
1. Build `mullvad-wireguard.dll`:
    1. Build `setupapihost`: `msbuild.exe setupapihost\setupapihost.vcxproj /p:Configuration=Release /p:Platform=x64`
    1. Build `api`: `msbuild.exe api\api.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off`
1. To sign `mullvad-wireguard.dll`, replace `<certificate-sha1-thumbprint>` in the following command and run it:
    `signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 /sha1 "<certificate-sha1-thumbprint>" /v /ac digicert-high-assurance-ev.crt Release\amd64\mullvad-wireguard.dll`
1. Copy `Release\amd64\mullvad-wireguard.dll` to `bin/dist/win10/`.

# Updating the binaries repository

Copy the following files from the `wireguard-nt` repository to `x86_64-pc-windows-msvc/wireguard-nt` in the `mullvadvpn-app-binaries` repository:
* `bin/dist/win10/mullvad-wireguard.dll`
* `bin/dist/mullvad-wireguard.pdb`
* `api/wireguard.h`