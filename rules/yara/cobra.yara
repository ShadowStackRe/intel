rule CobraRansomware {
    meta:
        description = "Rule to detect Cobra ransomware"
        author = "ShadowStackRe.com"
        date = "2024-06-30"
        Rule_Version = "v1"
        malware_type = "ransomware"
        malware_family = "Cobra"
        License = "MIT License, https://opensource.org/license/mit/"
        Hash = "bf0c353bf4f59db1d33b62589cca64d29c915d3073c86cd04e78f1d28bb65d74"
    strings:
        $ext = "COBRA" wide
        $svcHost = "svchost.exe" wide
        $readme = "cobra.txt" wide
        $appMutexRegEx = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" wide
        $ReadMeHdr = "YOUR FILES ARE ENCRYPTED By .COBRA!!!" wide
    condition:
        all of them and filesize < 2MB
}
