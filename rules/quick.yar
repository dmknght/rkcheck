private rule is_elf {
  condition:
    uint32(0) == 0x464c457f
}

rule HiDrootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "A port of chkrootkit's signature using file path matching to detect malware"
  condition:
    file_path == "/var/lib/games/.k"
}

rule t0rn {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "A port of chkrootkit's signature using file path matching to detect malware"
  condition:
    file_path == "/etc/ttyhash" or file_path == "/sbin/xlogin" or file_path == "/sbin/xlogin" or file_name == "ldlib.tk" or file_name == ".puta" or file_name == ".t0rn"
}

rule lion_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "A port of chkrootkit's signature using file path matching to detect malware"
  condition:
    file_path == "/bin/in.telnetd" or file_path == "bin/mjy" or file_path == "/usr/info/.torn" or file_path == "/dev/.lib"
}
