rule HelloFireRansomware {
    meta:
        description = "Rule to detect HelloFire ransomware"
        author = "ShadowStackRe.com"
        date = "2024-03-24"
        Rule_Version = "v1"
        malware_type = "ransomware"
        malware_family = "HelloFire"
        License = "MIT License, https://opensource.org/license/mit/"
        Hash = "3656c44fd59366700f9182278faf2b6b94f0827f62a8aac14f64b987141bb69b"
    strings:
        $strExt = ".afire" wide
        $strRestore = "Restore.txt" wide
        $strShadowCopy = "vssadmin.exe delete shadows /all /quiet" wide
        $strMutex = "MoreMoney"
        $strPDBPath1 = "Zdravstvuy"
        $strPDBPath2 = "e.pdb"
    condition:
        uint16(0) == 0x5A4D and
        all of them
}