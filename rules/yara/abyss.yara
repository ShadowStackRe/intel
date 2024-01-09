rule AbyssLocker {

meta:
      description = "rule to detect ESXi variant of AbyssLocker"
      author = "ShadowStackRe.com"
      date = "2023-08-13"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Ransom:Linux/AbyssLocker"
      hash1 = "72310e31280b7e90ebc9a32cb33674060a3587663c0334daef76c2ae2cc2a462"
      License = "MIT License, https://opensource.org/license/mit/"

strings:
    $usage_string = "Usage:%s [-m (5-10-20-25-33-50) -v -d] Start Path" ascii
    $audit_log = "work.log" ascii
    $prog_opts = "m:vdekc:" ascii
    $daemon_switch = "switch to daemon" ascii
    $encrypt_progress = "porgress %s:%.2f GB\ttotal %.2f GB\t%.2f sec.\t%.4f GB\\s" ascii
    $file_ext = ".crypt" ascii
    $readme_ext = ".README_TO_RESTORE" ascii
    $readme_note = "We are the Abyss Locker" ascii

condition:
    all of them
}