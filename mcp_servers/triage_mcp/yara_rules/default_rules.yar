rule SuspiciousTempExecutable {
    meta:
        description = "Executable in Temp / suspicious location"
        severity    = "HIGH"
    strings:
        $path1 = "\\Temp\\" nocase
        $path2 = "\\AppData\\Local\\Temp\\" nocase
        $path3 = "/tmp/" nocase
        $mz    = { 4D 5A }
    condition:
        $mz at 0 and any of ($path1, $path2, $path3)
}

rule MimikatzStrings {
    meta:
        description = "Mimikatz credential dumper strings"
        severity    = "CRITICAL"
    strings:
        $a = "sekurlsa" nocase
        $b = "lsadump" nocase
        $c = "mimikatz" nocase
        $d = "wdigest" nocase
    condition:
        2 of them
}

rule CobaltStrikeBeacon {
    meta:
        description = "Cobalt Strike beacon indicators"
        severity    = "CRITICAL"
    strings:
        $a = "cobaltstrike" nocase
        $b = "beacon.dll" nocase
        $c = "ReflectiveLoader" nocase
    condition:
        any of them
}

rule PowerShellEncodedCommand {
    meta:
        description = "PowerShell encoded command execution"
        severity    = "HIGH"
    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
        $d = "powershell" nocase
    condition:
        $d and any of ($a, $b, $c)
}

rule NetUserAddCommand {
    meta:
        description = "Unauthorized user account creation"
        severity    = "HIGH"
    strings:
        $a = "net user" nocase
        $b = "/add" nocase
        $c = "net localgroup administrators" nocase
    condition:
        ($a and $b) or $c
}

rule SuspiciousRegistryRun {
    meta:
        description = "Registry Run key persistence"
        severity    = "HIGH"
    strings:
        $a = "CurrentVersion\\Run" nocase
        $b = "CurrentVersion\\RunOnce" nocase
    condition:
        any of them
}
