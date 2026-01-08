# Install Certificate Authority

## Windows [Download {app_name}-ca-cert.cer](/{app_name}-ca-cert.cer)

#### Manual Installation (CER file):

1. Double-click the CER file.
2. Click "Install Certificate...".
3. Select a store location (Current User or Local Machine)
   and click Next.
4. Select "Place all certificates in the following store".
5. Click Browse, select "Trusted Root Certification
   Authorities", click OK, and click Next.
6. Click Finish.
7. Click Yes to confirm the security warning.

#### Automated Installation:

`certutil.exe -addstore root {app_name}-ca-cert.cer`

## Linux [Download {app_name}-ca-cert.pem](/{app_name}-ca-cert.pem)

#### Ubuntu/Debian:

1. `mv {app_name}-ca-cert.pem /usr/local/share/ca-certificates/{app_name}-ca-cert.crt`
2. `sudo update-ca-certificates`

#### Fedora:

1. `mv {app_name}-ca-cert.pem /etc/pki/ca-trust/source/anchors/`
2. `sudo update-ca-trust`

#### Arch Linux:

`sudo trust anchor --store {app_name}-ca-cert.pem`

## macOS [Download {app_name}-ca-cert.pem](/{app_name}-ca-cert.pem)

#### Manual Installation:

1. Double-click the PEM file to open Keychain Access.
2. Locate the new certificate "{app_name}" in the list and double-click it.
3. Change Secure Socket Layer (SSL) to Always Trust.
4. Close the dialog window and enter your password if prompted.

#### Automated Installation:

`sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain {app_name}-ca-cert.pem`

## iOS [Download {app_name}-ca-cert.pem](/{app_name}-ca-cert.pem)

1. Use Safari to download the certificate. Other browsers may not open the proper installation prompt.
2. Install the new Profile (Settings -> General -> VPN & Device Management).
3. **Important**: Go to Settings -> General -> About -> Certificate Trust Settings. Toggle {app_name} to ON.

## Android [Download {app_name}-ca-cert.cer](/{app_name}-ca-cert.cer)

#### Android 10+:

1. Open the downloaded CER file.
2. Enter "{app_name}" (or anything else) as the certificate name.
3. For credential use, select VPN and apps.
4. Click OK.

Some Android distributions require you to install the certificate via Settings -> Security -> Advanced -> Encryption and credentials -> Install a certificate -> CA certificate (or similar) instead.

> Warning: Apps that target Android API Level 24 (introduced in 2016) and above only accept certificates from the system trust store ([#2054](https://github.com/mitmproxy/mitmproxy/issues/2054)). User-added CAs are not accepted unless the application manually opts in. Except for browsers, you need to patch most apps manually ([Android network security config](https://developer.android.com/training/articles/security-config)).

## Firefox [Download {app_name}-ca-cert.pem](/{app_name}-ca-cert.pem)

1. Open Options -> Privacy & Security and click View Certificates... at the bottom of the page.
2. Click Import... and select the downloaded certificate.
3. Enable Trust this CA to identify websites and click OK.

---

Other users cannot intercept your connection. This page is served by your {app_name} instance. The certificate has been uniquely generated and is not shared.
