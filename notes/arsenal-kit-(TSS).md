
The arsenal kit is a group of collected scripts that can be imported to Cobalt Strike to perform a variety of different types of exploitation methods. We can create "aggressor" scripts which essentially do that - meaning we can make scripts for both pre-exploitation and post-exploitation attacks.

While Cobalt Strike does provide some basic obfuscation injections by default, we can drastically enhance these capabilities to bypass EDR and Defender using the artifact kit.

We can first start by altering a few basic objects, known as the artifacts. These make up the signatures and boiler plate code within our executables and scripts that we use to call back to our reverse shells.

# Defender/EDR Bypass Config

Many of the beacons that are formed from artifacts have the file `bypass-pipe.c` and `patch.c` injected into them. These files, written in `C` , contain data that can be modified. The signatures in these files generally are the signatures that Defender and EDR will pick up on.

![[Pasted image 20240306171125.png]]

We can start by checking `patch.c` and obfuscating some of the code.

```
for (x = 0; x < length; x++) {
    char* ptr = (char *)buffer + x;

    /* do something random */
    GetTickCount();

    *ptr = *ptr ^ key[x % 8];
}
```

Then, in `bypass-pipe.c` we can alter another bit of code, namely the `sprintf` pipe call which would normally also caught by Defender.

```
sprintf(pipename, "%c%c%c%c%c%c%c%c%cdaz\\today", 92, 92, 46, 92, 112, 105, 112, 101, 92);
```

We can also use the thread stack spoofing technique once we build our artifact kit, utilizing the `src-common/spoof.c` code snippet to leverage Fibres and switch the context of the beacon's sleep phase. This obscures the actual return address, which can bypass yara rules to an extent.

```
./build.sh "pipe" MapViewOfFile 350000 0 true true none /mnt/c/Tools/cobaltstrike/artifacts
```

We'll then be able to add the `.cna` script that is generated into the `Script Manager`. EXE and DLL beacons generated from hereon out will adopt the settings specified in the artifact kit.
