import "elf"
import "hash"


private rule is_elf {
  condition:
    uint32(0) == 0x464c457f
}

private rule elf_no_sections {
  condition:
    is_elf and elf.number_of_sections == 0
}

rule Suspicious_ELF_NoSection {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Suspicious ELF files. File has no section and file size < 1KB. Usually see by Metasploit's stageless payloads"
  condition:
    elf_no_sections and filesize < 1KB
}

rule Metasploit_Payload_Staged {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Scan Metasploit's Linux staged payload by checking section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "fbeb0b6fd7a7f78a880f68c413893f36"
    )
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
    file_path == "/etc/ttyhash" or file_path == "/sbin/xlogin" or file_path == "/sbin/xlogin"
     or file_name == "ldlib.tk" or file_name == ".puta" or file_name == ".t0rn"
}

rule lion_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "A port of chkrootkit's signature using file path matching to detect malware"
  condition:
    file_path == "/bin/in.telnetd" or file_path == "bin/mjy" or file_path == "/usr/info/.torn"
    or file_path == "/dev/.lib"
}

rule rsha_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "A port of chkrootkit's signature using file path matching to detect malware"
  condition:
    file_name == "kr4p" or file_path == "/usr/bin/n3tstat" or file_path == "/usr/bin/chsh2"
    or file_path == "/usr/bin/slice2" or file_name == ".1proc" or file_name == ".1addr"
    or file_path == "/etc/rc.d/rsha" or file_path == "/etc/rc.d/arch/alpha/lib/.lib"
}
