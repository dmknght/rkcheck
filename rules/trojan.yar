import "elf"
import "hash"
include "rules/magics.yar"


// rule Trojan_3
// {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux Trojan. Some AV vendors can't detect. https://www.virustotal.com/gui/file/6469fcee5ede17375b74557cdd18ef6335c517a4cccfff86288f07ff1761eaa7"
//   condition:
//     is_elf and
//     for any i in (0 .. elf.number_of_sections - 1): (
//       hash.md5(elf.sections[i].offset, elf.sections[i].size) == "bbe7d25b87e2b810db57b6d532b10d09"
//     )
// }

rule Agent_4b06
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "4b060ab45f7acc1b2959dd5969f97a45d6fecd06f311763afbb864eaea4161e4"
    vrt_report = "https://www.virustotal.com/gui/file/4b060ab45f7acc1b2959dd5969f97a45d6fecd06f311763afbb864eaea4161e4"
    /*
      Uncommon imports: fexecve, syscall, getpid)
      Uncommon strings: "pid,%d", "no_elf",
      Code (function main):
        uVar1 = getpid();
        printf("pid,%d", uVar1);
        uVar1 = syscall(0x13f, "no_elf", 1);
        write(uVar1, 0x400988, 0x100);
        fexecve(uVar1, &var_20h, &var_10h);
    */
  strings:
    $str1 = { 70 69 64 2C 25 64 } // "pid,%d"
    $str2 = { 6E 6F 5F 65 6C 66 } // "no_elf"
    $str3 = { 63 6F 6D 70 6C 65 74 65 64 2E 37 35 39 34 } // "completed.7594"
  condition:
    (is_elf and elf.symtab[62].name == "fexecve@@GLIBC_2.2.5" and elf.symtab[63].name == "syscall@@GLIBC_2.2.5" and
      elf.symtab[54].name == "getpid@@GLIBC_2.2.5")
    or all of them
}

// rule Agent_2
// {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     vrt_report = "https://www.virustotal.com/gui/file/edbee3b92100cc9a6a8a3c1a5fc00212627560c5e36d29569d497613ea3e3c16"
//     // symbols: imp.getpid and imp.execvp
//     // strings (static) E: neither argv[0] nor $_ works.
//     // runtime strings /root/analyzed_bin and applet not found
//     // TODO need to test process scan
//   strings:
//     $1 = { 2F 72 6F 6F 74 2F 61 6E 61 6C 79 7A 65 64 5F 62 69 6E } // "/root/analyzed_bin"
//     $2 = { 61 70 70 6C 65 74 20 6E 6F 74 20 66 6F 75 6E 64 } // "applet not found"
//   condition:
//     (is_elf and hash.md5(elf.sections[16].offset, elf.sections[16].size) == "f3a96941a385fc9062269babdb5cbc02") or
//     all of them
// }


// rule Python_IRCBot
// {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Python IRCBot, Unknown Trojan malware. Likely compiled from Python scripts"
//     /*
//       Hash of .shstrtab 98c978a3d9f51f870ec65edc9a224bf8 matches as well but i don't know if all files compiled from python is detected
//       as wrong behavior
//     */
//   condition:
//     is_elf and
//     for any i in (0 .. elf.number_of_sections - 1): (
//       hash.md5(elf.sections[i].offset, elf.sections[i].size) == "196b7c3bdcb1a697395053b23b25abce"
//     )
// }

rule EzuriLoader_Golang_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect file by section hash for EzuriLoader's Golang binaries"
    reference = "https://www.virustotal.com/gui/file/751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
    hash = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
  condition:
    is_elf and hash.md5(elf.sections[3].offset, elf.sections[3].size) == "dfd54f22d3a3bb072d34c424aa554500"
}


rule Metasploit_Stageless_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "26/12/2021"
    description = "Scan Metasploit's Linux Stageless by checking strings or section hash. Current rule doesn't match encoded malware"
  strings:
    // $ = { 2D 70 2C 20 2D 2D 70 65 72 73 69 73 74 20 5B 6E 6F 6E 65 7C 69 6E 73 74 61 6C 6C 7C 75 6E 69 6E 73 74 61 6C 6C 5D 20 6D 61 6E 61 67 65 20 70 65 72 73 69 73 74 65 6E 63 65 } // "-p, --persist [none|install|uninstall] manage persistence"
    $ = { 6D 61 6E 61 67 65 20 70 65 72 73 69 73 74 65 6E 63 65 } // "manage persistence"
    $ = { 73 65 73 73 69 6F 6E 2D 67 75 69 64 } // "session-guid"
    $ = { 4D 53 46 5F 4C 49 43 45 4E 53 45 } // "MSF_LICENSE"
    // $ = { 70 72 6F 63 65 73 73 5F 6E 65 77 3A 20 67 6F 74 20 25 7A 64 20 62 79 74 65 20 65 78 65 63 75 74 61 62 6C 65 20 74 6F 20 72 75 6E 20 69 6E 20 6D 65 6D 6F 72 79 } // "process_new: got %zd byte executable to run in memory"
  condition:
    // Check for file only
    (is_elf and hash.md5(elf.sections[21].offset, elf.sections[21].size) == "fbeb0b6fd7a7f78a880f68c413893f36") or
    // Check file or memory's strings
    all of them
}


rule Excedoor_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Excedoor"
    date = "28/12/2021"
    refrence = "https://otx.alienvault.com/indicator/file/6138054a7de11c23b5c26755d7548c4096fa547cbb964ac78ef0fbe59d16c2da"
    hash = "3d06f85ac19dc1a6f678aa4e28ce5c42"
    file_type = "ELF32"
  strings:
    $s_1 = { 70 61 73 73 77 64 66 6F 72 79 61 62 61 62 65 } // "passwdforyababe"
    $s_2 = { 73 68 61 64 6F 77 66 6F 72 79 61 62 61 62 65 } // "shadowforyababe"
    $s_3 = { 67 61 79 7A 30 72 40 62 6F 69 2E 6F 72 67 2E 69 65 } // "gayz0r@boi.org.ie"
    $s_4 = { 42 72 61 6E 64 20 6E 65 77 20 54 43 50 20 72 6F 6F 74 20 73 68 65 6C 6C 21 } // "Brand new TCP root shell!"
  condition:
    (is_elf and for any i in (0 .. elf.symtab_entries - 1): ( // Detect file by function name / obj names
      (elf.symtab[i].type == elf.STT_OBJECT and (elf.symtab[i].name == "mailpasswd" or elf.symtab[i].name == "mailshadow")) or
      (elf.symtab[i].type == elf.STT_FUNC and elf.symtab[i].name == "bindshell")
    )) or
    ($s_1 and $s_2 and $s_3) or // Detect strings in memory / file
    $s_4 // Heuristic level
}

rule EkoBackdoor_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux EkoBackdoor"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/74d29efbdf7df9bb7e51fad039e0e40455795056ec643610b38853c602a4357c"
    target = "File, memory"
  strings:
    $spec_1 = { 42 61 63 6B 64 6F 6F 72 20 69 6E 73 74 61 6C 61 64 6F 21 20 2D 20 48 61 76 65 20 61 20 6E 69 63 65 20 68 61 63 6B 20 3B 29 } // "Backdoor instalado! - Have a nice hack ;)"
    $spec_2 = { 43 6F 64 65 64 20 62 79 20 63 61 30 73 20 2F 20 45 7A 6B 72 61 63 68 6F 20 54 65 61 6D 20 3E } // "Coded by ca0s / Ezkracho Team >"
    $spec_3 = { 45 6B 6F 42 61 63 6B 64 6F 6F 72 20 76 31 2E 31 20 62 79 20 63 61 30 73 } // "EkoBackdoor v1.1 by ca0s"
    $spec_4 = { 65 6B 6F 72 75 6C 65 7A } // "ekorulez"
    $spec_5 = { 73 74 72 65 61 6D 20 74 63 70 20 6E 6F 77 61 69 74 20 72 6F 6F 74 20 2F 62 69 6E 2F 73 68 20 73 68 20 2D 69 } // "stream tcp nowait root /bin/sh sh -i"
    $cmd_2 = { 63 70 20 2F 62 69 6E 2F 73 68 20 2F 74 6D 70 2F 73 68 } // "cp /bin/sh /tmp/sh"
    $cmd_3 = { 63 68 6D 6F 64 20 34 37 31 31 20 2F 74 6D 70 2F 73 68 } // "chmod 4711 /tmp/sh"
    $cmd_4 = { 2E 2F 65 6B 6F 62 64 6F 6F 72 } // "./ekobdoor"
  condition:
    any of ($spec_*) or all of ($cmd_*)
}

rule Explodor_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Explodor"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/fb5eba7a927ce0513e11cde7a496009453f2d57b72c73fcbe04e9a527a3eabac"
    target = "File, memory"
  strings:
    $3 = { 55 6E 61 62 6C 65 20 74 6F 20 73 70 61 77 6E 20 73 68 65 6C 6C } // "Unable to spawn shell"
    $4 = { 6B 65 6C 64 40 64 6B 75 75 67 2E 64 6B } // "keld@dkuug.dk"
    $5 = { 50 41 54 48 3D 2F 75 73 72 2F 62 69 6E 3A 2F 62 69 6E 3A 2F 75 73 72 2F 73 62 69 6E 3A 2F 73 62 69 6E } // "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
  condition:
    all of them
}

rule Homeunix_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Homeunix"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/ced749fecb0f9dde9355ee29007ea8a20de277d39ebcb5dda61cd290cd5dbc02"
    target = "File, memory"
  strings:
    $s1 = { 75 6E 69 78 66 6F 72 63 65 3A 3A 30 3A 30 3A 75 6E 69 78 66 6F 72 63 65 3A 2F 72 6F 6F 74 3A 2F 62 69 6E 2F 62 61 73 68 } // "unixforce::0:0:unixforce:/root:/bin/bash"
    $s2 = { 2F 65 74 63 2F 70 61 73 73 77 64 } // "/etc/passwd"
  condition:
    all of them
}

rule Fysbis_364f {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Fysbis"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91"
    reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
    reference = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Sofacy_Fysbis.yar"
    reference = "https://www.hybrid-analysis.com/sample/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
    target = "File, memory"
    hash = "364ff454dcf00420cff13a57bcb78467"
  strings:
    $addr_1 = { 61 7A 75 72 65 6F 6E 2D 6C 69 6E 65 2E 63 6F 6D } // "azureon-line.com"
    $path_1 = { 2E 63 6F 6E 66 69 67 2F 64 62 75 73 2D 6E 6F 74 69 66 69 65 72 } // ".config/dbus-notifier" // full path: .config/dbus-notifier/dbus-inotifier
    $path_2 = { 2E 6C 6F 63 61 6C 2F 63 76 61 2D 73 73 79 73 } // ".local/cva-ssys"
    $path_3 = { 7E 2F 2E 63 6F 6E 66 69 67 2F 61 75 74 6F 73 74 61 72 74 } // "~/.config/autostart"
    $cmd_1 = { 72 6D 20 2D 66 20 7E 2F 2E 63 6F 6E 66 69 67 2F 61 75 74 6F 73 74 61 72 74 2F } // "rm -f ~/.config/autostart/"
    $cmd_2 = { 72 6D 20 2D 66 20 2F 75 73 72 2F 6C 69 62 2F 73 79 73 74 65 6D 64 2F 73 79 73 74 65 6D 2F } // "rm -f /usr/lib/systemd/system/"
    $cmd_3 = { 6D 6B 64 69 72 20 2F 75 73 72 2F 6C 69 62 2F 63 76 61 2D 73 73 79 73 } // "mkdir /usr/lib/cva-ssys"
    $cmd_4 = { 6D 6B 64 69 72 20 7E 2F 2E 63 6F 6E 66 69 67 2F 61 75 74 6F 73 74 61 72 74 } // "mkdir ~/.config/autostart" // Could be false positive
    // Generated when malware is executed as sudo. This is the systemd unit
    $entry_1 = { 45 78 65 63 53 74 61 72 74 3D 2F 62 69 6E 2F 72 73 79 6E 63 64 } // ExecStart=/bin/rsyncd
    $entry_2 = { 44 65 73 63 72 69 70 74 69 6F 6E 3D 20 73 79 6E 63 68 72 6F 6E 69 7A 65 20 61 6E 64 20 62 61 63 6B 75 70 20 73 65 72 76 69 63 65 } // Description= synchronize and backup service
  condition:
    /*
    This rule works for dump file from gcore. It doesn't work for memory scan
    for any i in (0 .. elf.number_of_segments): (
      4 of ($path_*, $cmd_*, $addr_*) in (elf.segments[i].offset .. elf.segments[i].offset + elf.segments[i].file_size)
    )
    */
    (is_elf and for any i in (0 .. elf.number_of_sections - 1): (
      elf.sections[i].name == ".rodata" and
      4 of ($path_*, $cmd_*, $addr_*) in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
    )) or 
    (4 of ($path_*, $cmd_*, $addr_*) in (0x418d00 .. 0x41a4ff)) or // Memory scan
    ($path_1 and xdg_desktop_entry) or // desktop file, startup as user
    ($entry_1 and $entry_2) // systemd unit, startup as root
}

rule Gbkdoor_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Gbkdoor"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/a1439937c8a383f010a071130aaae4443de6b7f4f7e71789c9964ea3a9d7f4a8"
    target = "File, memory"
  strings:
    $1 = { 6D 6D 65 6E 65 67 68 69 6E 40 69 6E 77 69 6E 64 2E 69 74 } // "mmeneghin@inwind.it"
    $2 = { 61 73 20 69 66 20 79 6F 75 20 61 72 65 20 72 6F 6F 74 2C 20 62 75 74 20 74 68 65 20 66 69 6C 65 20 74 6F 20 74 72 6F 6A 61 6E 69 7A 65 20 6D 75 73 74 20 62 65 20 73 75 69 64 72 6F 6F 74 21 } // "as if you are root, but the file to trojanize must be suidroot!"
    $3 = { 6E 6F 77 2C 20 79 6F 75 20 63 61 6E 20 65 61 73 69 6C 79 20 75 73 65 20 74 68 65 20 62 61 63 6B 64 6F 6F 72 20 69 6E 73 74 61 6C 6C 65 64 20 73 6F 3A } // "now, you can easily use the backdoor installed so:"
  condition:
    $1 or ($2 and $3)
}

rule Gummo {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Gummo"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/67b9ddd4a21a78ff1a4adbf4b2fb70d279c79494d34e6e2e12673eed134f0d5f"
    target = "File, memory"
  strings:
    $ = { 65 63 68 6F 20 72 65 77 74 3A 3A 30 3A 30 3A 3A 2F 3A 2F 62 69 6E 2F 73 68 3E 3E 2F 65 74 63 2F 70 61 73 73 77 64 3B } // "echo rewt::0:0::/:/bin/sh>>/etc/passwd;"
  condition:
    all of them
}

rule KBD {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux KBD"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/3aba59e8bbaecf065d05b7a74655668484bb16fdec589b8e7d169e4adf65d840"
    target = "File, memory"
  strings:
    $1 = { 59 6F 75 72 20 4B 75 6E 67 2D 46 75 20 69 73 20 67 6F 6F 64 2E } // "Your Kung-Fu is good."
    $2 = { 6F 72 69 67 5F 73 74 61 74 } // "orig_stat"
    $3 = { 62 64 5F 67 65 74 75 69 64 } // "bd_getuid"
    $4 = { 6F 72 69 67 5F 67 65 74 75 69 64 } // "orig_getuid"
  condition:
    all of them
}

rule Sckit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "ELF:Sckit-A, Unix.Trojan.Suki-1, Backdoor:Linux/Rooter"
    date = "13/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/db4c0fe28e8fdce6f7b7e2e12738ff84f084667e07b408dc04dc92bd074bc0e2"
    target = "File, memory"
  strings:
    $1 = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:./bin:/etc/.MG:/etc/.MG/bin"
    $2 = "HOME=/etc/.MG"
    $3 = "HISTFILE=/dev/null"
  condition:
    2 of them
}

rule Earthworm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $1 = "Earthworm is a network agent tool."
    $2 = "rootkiter : The creator"
    $3 = "darksn0w  : Proviede some advice"
    $4 = "zhuanjia  : Modify the Readme file"
    $5 = "syc4mor3  : Named for this tool"
    $6 = "http://rootkiter.com/EarthWrom/"
  condition:
    3 of them
}

rule BashDoor {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $1 = "Compiling SeCshell"
    $2 = "-=[1]=- Update and backdoor Bash."
    $3 = "-=[2]=- Compile and install SeCshell."
    $4 = "nU.ajj1cF2Qk6"
  condition:
    any of them
}

rule MushDoor {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $1 = "mushd00r"
    $2 = "username to hide  & processes"
  condition:
    all of them
}

rule ICMP_Backdoor {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "icmp-backdoor"
    $2 = "you need to be root!"
  condition:
    all of them
}

rule Lyceum {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "d:D:s:S:l:p:P:u:x:i:b:I"
    $ = "icmp moonbouce backdoor"
    $ = "bi-spoofed icmp backdoor"
    $ = "spoof all packets"
  condition:
    any of them
}

rule Silencer {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = /backdoor[d]_BEGIN/
    $2 = "ready for injection.."
    $3 = "0x4553-Silencer"
    $4 = "by BrainStorm and Ares"
  condition:
    any of them
}

rule Sneaky {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "i:l:t:s:S:d:D:"
    $2 = "[Sneaky@%s]#"
    $3 = "Phish@mindless.com"
  condition:
    any of them
}

rule Galore {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "Backdoor Galore By NTFX"
  condition:
    any of them
}

rule BlueDragon_sfe {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "tHE rECIdjVO"
    $2 = "<recidjvo@pkcrew.org>"
  condition:
    any of them
}

rule Rrs {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "hlp:b:r:R:t:Dqk:x:sS:P:c:v:C:e:m0LV"
  condition:
    any of them
}

rule Necro {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "N3Cr0m0rPh"
  condition:
    any of them
}

rule PunBB {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "change_email SQL injection exploit"
    $ = "PunBB"
  condition:
    all of them
}

rule keylogger_xspy {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "15/12/2021"
    target = "File, memory"
  strings:
    // string from dumped mem + source code
    $str_1 = "blah...."
    $str_2 = "opened %s for snoopng"
    $str_3 = "%s: can't open display %s"
    // function call, also in source code, dump string. Those strings caused false positives
    // $call_1 = "XKeycodeToKeysym"
    // $call_2 = "XKeysymToString"
    // $call_3 = "XQueryKeymap"
    // $call_4 = "XDisplayKeycodes"
    // $call_5 = "XOpenDisplay"
  condition:
    // (all of ($str_*)) or (all of ($call_*))
    all of them
}


rule exploit_dirtycow {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "15/12/2021"
    target = "Memory"
    hash = "0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
    reference = "https://www.virustotal.com/gui/file/0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
  strings:
    $1 = "/etc/passwd"
    $2 = "/tmp/passwd.bak"
    $3 = "root"
    $4 = "Please enter the new password:"
    // $5 = "You can log in with the username"
    $6 = "DON'T FORGET TO RESTORE!"
  condition:
    all of them
}

// TODO 1384790107a5f200cab9593a39d1c80136762b58d22d9b3f081c91d99e5d0376 (upx)
// hash unpacked: afb6ec634639a68624c052d083bbe28a0076cd3ab3d9a276c4b90cb4163b8317 golang malware
// TODO 139b09543494ead859b857961d230a39b9f4fc730f81cf8445b6d83bacf67f3d: malware downloader rule34 python compiled file

rule TinyShell {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Open-source TinyShell backdoor"
    reference = "https://github.com/creaktive/tsh"
    // execl, setsid is in imports, type: func
  strings:
    $1 = "s:p:c::" // getopt strings
    $2 = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]" // Usage
  condition:
    is_elf and all of them
}


rule UNC1945_STEELCORGI_packed{
  meta:
    description = "Yara Rule for packed ELF backdoor of UNC1945"
    author = "Yoroi Malware Zlab"
    last_updated = "2020_12_21"
    tlp = "white"
    category = "informational"
    reference = "https://yoroi.company/research/opening-steelcorgi-a-sophisticated-apt-swiss-army-knife/"
  strings:
    $s1={4? 88 47 3c c1 6c ?4 34 08 8a 54 ?? ?? 4? 88 57 3d c1 6c}
    $s2={0f b6 5? ?? 0f b6 4? ?? 4? c1 e2 18 4? c1 e0 10 4? }
    $s3={8a 03 84 c0 74 ?? 3c 3d 75 ?? 3c 3d 75 ?? c6 03 00 4? 8b 7d 00}
    $s4={01 c6 89 44 ?? ?? 8b 44 ?? ?? 31 f2 89 74 ?? ?? c1}
    $s5={ 4? 89 d8 4? 31 f2 4? c1 e0 13 4? 01 d7 4? }
  condition:
    is_elf and 3 of them
}


rule UNC1945_STEELCORGI_generic{
  meta:
    description = "Yara Rule for unpacked ELF backdoor of UNC1945"
    author = "Yoroi Malware Zlab"
    last_updated = "2020_12_21"
    tlp = "white"
    category = "informational"
    reference = "https://yoroi.company/research/opening-steelcorgi-a-sophisticated-apt-swiss-army-knife/"
  strings:
    $s1="MCARC"
    $s2="833fc0088ea41bc3331db60ae2.debug"
    $s3="PORA1022"
    $s4="server"
    $s5="test"
    $s6="no ejecutar git-update-server-info"
    $s7="dlopen"
    $s8="dlsym"
    $s9="5d5c6da19e62263f67ca63f8bedeb6.debug"
    $s10={72 69 6E 74 20 22 5B 56 5D 20 41 74 74 65 6D 70 74 69 6E 67 20 74 6F 20 67 65 74 20 4F 53 20 69 6E 66 6F 20 77 69 74 68 20 63 6F 6D 6D 61 6E 64 3A 20 24 63 6F 6D 6D 61 6E 64 5C 6E 22 20 69 66 20 24 76 65 72 62 6F 73 65 3B}

  condition:
    all of them and #s4>50 and #s5>20
}

rule Gasit_ada7 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "946689ba1b22d457be06d95731fcbcac"
  strings:
    $1 = "GASIT *  %s:%s %s port: %s" fullword
    $2 = "Gasit: %d" fullword
    $3 = "root@haiduc:~> GO!!!" fullword
    $4 = "gasite.txt" fullword
  condition:
    2 of them
}