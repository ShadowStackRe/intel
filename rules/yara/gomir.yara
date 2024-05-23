rule GomirBackdoor {
    meta:
        description = "Rule to detect Gomir Backdoor"
        author = "ShadowStackRe.com"
        date = "2024-05-22"
        Rule_Version = "v1"
        malware_type = "backdoor"
        malware_family = "gomir"
        License = "MIT License, https://opensource.org/license/mit/"
        Hash = "30584f13c0a9d0c86562c803de350432d5a0607a06b24481ad4d92cdf7288213"
    strings:
        $strCronText = "cron.txt"
        $strHttpResPathMIR = "mir/"
        $strSystemDSvc = "syslogd.service"
        $strSocksList = "Socks list"
        $strCmdPath = "CmdPath:"
        $strCodePage = "Codepage:"
        $strNextConnTime = "Next Connection Time:"
        $strTCPOpenedIndicator = {
            C7 44 24 29 5B 2B 5D 20
            C7 44 24 2C 20 4F 70 65
            C7 44 24 30 6E 65 64 2E
        }
    condition:
        all of them and filesize < 6MB
}
