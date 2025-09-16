rule Ransomware_Generic {
    meta:
        description = "Generic ransomware detection patterns"
        author = "MUSAFIR SecOps"
        severity = "critical"
        category = "malware"
        tags = "ransomware,malware,encryption"
    
    strings:
        $s1 = "encrypt" ascii
        $s2 = "decrypt" ascii
        $s3 = "ransom" ascii
        $s4 = "bitcoin" ascii
        $s5 = "wallet" ascii
        $s6 = "payment" ascii
        $s7 = "restore" ascii
        $s8 = "recover" ascii
        $s9 = "locked" ascii
        $s10 = "unlock" ascii
        $s11 = "key" ascii
        $s12 = "crypt" ascii
        $s13 = "AES" ascii
        $s14 = "RSA" ascii
        $s15 = "encrypted" ascii
        $s16 = "decrypted" ascii
        $s17 = "cipher" ascii
        $s18 = "algorithm" ascii
        $s19 = "password" ascii
        $s20 = "secret" ascii
        
    condition:
        5 of ($s*)
}

rule Ransomware_File_Extensions {
    meta:
        description = "Ransomware file extension patterns"
        author = "MUSAFIR SecOps"
        severity = "high"
        category = "malware"
        tags = "ransomware,file_extensions"
    
    strings:
        $ext1 = ".encrypted"
        $ext2 = ".locked"
        $ext3 = ".crypted"
        $ext4 = ".crypt"
        $ext5 = ".enc"
        $ext6 = ".locked"
        $ext7 = ".crypto"
        $ext8 = ".cryptolocker"
        $ext9 = ".cerber"
        $ext10 = ".locky"
        
    condition:
        1 of ($ext*)
}

rule Suspicious_Process_Names {
    meta:
        description = "Suspicious process names commonly used by malware"
        author = "MUSAFIR SecOps"
        severity = "medium"
        category = "suspicious"
        tags = "process,malware,suspicious"
    
    strings:
        $proc1 = "wscript.exe"
        $proc2 = "cscript.exe"
        $proc3 = "powershell.exe"
        $proc4 = "cmd.exe"
        $proc5 = "rundll32.exe"
        $proc6 = "regsvr32.exe"
        $proc7 = "mshta.exe"
        $proc8 = "certutil.exe"
        $proc9 = "bitsadmin.exe"
        $proc10 = "wmic.exe"
        
    condition:
        1 of ($proc*)
}
