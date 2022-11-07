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
    $str1 = "pid,%d"
    $str2 = "no_elf"
    $str3 = "completed.7594"
  condition:
    (is_elf and elf.symtab[62].name == "fexecve@@GLIBC_2.2.5" and elf.symtab[63].name == "syscall@@GLIBC_2.2.5" and
      elf.symtab[54].name == "getpid@@GLIBC_2.2.5")
    or all of them
}


rule SSHD_95d7 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "SSH Backdoor"
    md5 = "95d7335fa643949534f128795c8ac21c"
  strings:
    $1 = "Rhosts Authentication disabled, originating port %d not trusted." ascii
    $2 = "kHgn4vlwonyP" fullword ascii
  condition:
    (
      is_elf and for any i in (0 .. elf.number_of_sections):
      (
        all of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      )
    )
    or
    for any i in (0 .. elf.number_of_segments):
    (
      all of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
    )
}


rule Agent_849b {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    md5 = "849b45fee92762d2b6ec31a11e1bcd76"
    description = "A Nim infector malware"
  strings:
    $1 = "akpcTVEZHXJe8ZbbQdHsSA" // Contains in strtab. Static binary only
    // 2 strings should show at runtime.
    $2 = "/tmp/.host"
    $3 = "The more you know... :)"
  condition:
  (
    is_elf and for any i in (0 .. elf.number_of_sections):
    (
      $1 in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
    )
  )
  or ($2 and $3)
}


rule Agent_be4d {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    md5 = "be4d3133afee0f4da853430339ba379f"
  strings:
    $1 = "/tmp/.server.sig" fullword ascii
    $2 = "touch /tmp/elevate" fullword ascii
    $3 = "/c.php?authkey=" fullword ascii
  condition:
    (
      is_elf and for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      )
    )
    or
    for any i in (0 .. elf.number_of_segments):
    (
      any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
    )
}


rule Kowai_f06a {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    md5 = "f06a780e653c680e2e4ddab4b397ddd2"
  strings:
    $1 = "KOWAI-BAdAsV" fullword ascii
    $2 = "KOWAI-d" fullword ascii
  condition:
    (
      is_elf and for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      )
    )
    or
    for any i in (0 .. elf.number_of_segments):
    (
      any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
    )
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

rule EzuriLoader_Generic
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


rule Metasploit_Stageless {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "26/12/2021"
    description = "Scan Metasploit's Linux Stageless by checking strings or section hash. Current rule doesn't match encoded malware"
  strings:
    $ = "manage persistence"
    $ = "session-guid"
    $ = "MSF_LICENSE"
    $ = "mettle_get_machine_id"
    $ = "mettle_get_procmgr"
    $ = "/mettle/mettle/src/"
  condition:
    // Check for file only
    (is_elf and hash.md5(elf.sections[21].offset, elf.sections[21].size) == "fbeb0b6fd7a7f78a880f68c413893f36") or
    // Check file or memory's strings
    3 of them
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
    $s_1 = "passwdforyababe"
    $s_2 = "shadowforyababe"
    $s_3 = "gayz0r@boi.org.ie"
    $s_4 = "Brand new TCP root shell!"
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
    $spec_1 = "Backdoor instalado! - Have a nice hack ;)"
    $spec_2 = "Coded by ca0s / Ezkracho Team >"
    $spec_3 = "EkoBackdoor v1.1 by ca0s"
    $spec_4 = "ekorulez"
    $spec_5 = "stream tcp nowait root /bin/sh sh -i"
    $cmd_2 = "cp /bin/sh /tmp/sh"
    $cmd_3 = "chmod 4711 /tmp/sh"
    $cmd_4 = "./ekobdoor"
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
    $3 = "Unable to spawn shell"
    $4 = "keld@dkuug.dk"
    $5 = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
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
    $s1 = "unixforce::0:0:unixforce:/root:/bin/bash"
    $s2 = "/etc/passwd"
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
    $addr_1 = "azureon-line.com" nocase
    $path_1 = ".config/dbus-notifier" // full path: .config/dbus-notifier/dbus-inotifier
    $path_2 = ".local/cva-ssys"
    $path_3 = "~/.config/autostart"
    $cmd_1 = "rm -f ~/.config/autostart/"
    $cmd_2 = "rm -f /usr/lib/systemd/system/"
    $cmd_3 = "mkdir /usr/lib/cva-ssys"
    $cmd_4 = "mkdir ~/.config/autostart" // Could be false positive
    // Generated when malware is executed as sudo. This is the systemd unit
    $entry_1 = "ExecStart=/bin/rsyncd"
    $entry_2 = "Description= synchronize and backup service"
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
    $1 = "mmeneghin@inwind.it"
    $2 = "as if you are root, but the file to trojanize must be suidroot!"
    $3 = "now, you can easily use the backdoor installed so:"
  condition:
    $1 or ($2 and $3)
}

rule Gummo_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Gummo"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/67b9ddd4a21a78ff1a4adbf4b2fb70d279c79494d34e6e2e12673eed134f0d5f"
    target = "File, memory"
  strings:
    $ = "echo rewt::0:0::/:/bin/sh>>/etc/passwd;"
  condition:
    all of them
}

rule KBD_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux KBD"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/3aba59e8bbaecf065d05b7a74655668484bb16fdec589b8e7d169e4adf65d840"
    target = "File, memory"
  strings:
    $1 = "Your Kung-Fu is good."
    $2 = "orig_stat"
    $3 = "bd_getuid"
    $4 = "orig_getuid"
  condition:
    all of them
}

rule Sckit_Generic {
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

rule Earthworm_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $1 = "Earthworm"
    $2 = "rootkiter"
    $3 = "darksn0w"
    $4 = "zhuanjia"
    $5 = "syc4mor3"
  condition:
    3 of them
}

rule BashDoor_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $1 = "SeCshell" nocase
    $2 = "Update and backdoor"
    $3 = "bash"
    $4 = "nU.ajj1cF2Qk6"
  condition:
    2 of them
}

rule MushDoor_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $1 = "mushd00r"
    $2 = "username to hide"
  condition:
    all of them
}

rule IcmpBackdoor_Generic {
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

rule Lyceum_Generic {
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

rule Silencer_Generic {
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

rule Sneaky_Generic {
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

rule Galore_Generic {
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

rule Rrs_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "hlp:b:r:R:t:Dqk:x:sS:P:c:v:C:e:m0LV"
  condition:
    any of them
}

rule Necro_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "N3Cr0m0rPh"
  condition:
    any of them
}

rule PunBB_Generic {
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

rule Xspy_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "15/12/2021"
    target = "File, memory"
  strings:
    // string from dumped mem + source code
    $str_1 = "blah...."
    $str_2 = "opened %s for snoopng"
    $str_3 = "can't open display"
  condition:
    all of them
}


rule Exploit_DirtyCow {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "1/11/2022"
    hash = "0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
    reference = "https://www.virustotal.com/gui/file/0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
  strings:
    $i_1 = "crypt" fullword ascii
    $i_2 = "madvise" ascii
    $i_3 = "pthread_create" ascii
    $i_4 = "ptrace" ascii
    $i_5 = "waitpid" fullword ascii
    $i_6 = "getpass" fullword ascii
    $s_1 = "/tmp/passwd.bak" ascii
    $s_2 = "madvise %d" fullword ascii
    $s_3 = "ptrace %d" fullword ascii
    $s_4 = "DON'T FORGET TO RESTORE!" ascii
  condition:
    elf.type != elf.ET_DYN and
    (
      is_elf and for any i in (0 .. elf.number_of_sections):
      (
        // Detect by import functions
        elf.sections[i].type == elf.SHT_STRTAB and all of ($i_*) in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      )
      or for any i in (0 .. elf.number_of_segments):
      (
        all of ($s_*) in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
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
    is_elf and for any i in (0 .. elf.number_of_sections):
    (
      all of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
    )
    or for any i in (0 .. elf.number_of_segments):
    (
      all of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
    )
}


rule UNC1945_STEELCORGI_packed {
  meta:
    description = "Yara Rule for packed ELF backdoor of UNC1945"
    author = "Yoroi Malware Zlab"
    last_updated = "2020_12_21"
    tlp = "white"
    category = "informational"
    reference = "https://yoroi.company/research/opening-steelcorgi-a-sophisticated-apt-swiss-army-knife/"
  strings:
    $s1 = {4? 88 47 3c c1 6c ?4 34 08 8a 54 ?? ?? 4? 88 57 3d c1 6c}
    $s2 = {0f b6 5? ?? 0f b6 4? ?? 4? c1 e2 18 4? c1 e0 10 4? }
    $s3 = {8a 03 84 c0 74 ?? 3c 3d 75 ?? 3c 3d 75 ?? c6 03 00 4? 8b 7d 00}
    $s4 = {01 c6 89 44 ?? ?? 8b 44 ?? ?? 31 f2 89 74 ?? ?? c1}
    $s5 = { 4? 89 d8 4? 31 f2 4? c1 e0 13 4? 01 d7 4? }
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
    $s1 = "MCARC"
    $s2 = "833fc0088ea41bc3331db60ae2.debug"
    $s3 = "PORA1022"
    $s4 = "server"
    $s5 = "test"
    $s6 = "no ejecutar git-update-server-info"
    $s7 = "dlopen"
    $s8 = "dlsym"
    $s9 = "5d5c6da19e62263f67ca63f8bedeb6.debug"
    $s10 = {72 69 6E 74 20 22 5B 56 5D 20 41 74 74 65 6D 70 74 69 6E 67 20 74 6F 20 67 65 74 20 4F 53 20 69 6E 66 6F 20 77 69 74 68 20 63 6F 6D 6D 61 6E 64 3A 20 24 63 6F 6D 6D 61 6E 64 5C 6E 22 20 69 66 20 24 76 65 72 62 6F 73 65 3B}

  condition:
    all of them and #s4 > 50 and #s5 > 20
}

rule Gasit_ada7 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "946689ba1b22d457be06d95731fcbcac"
  strings:
    $1 = "GASIT"
    $3 = "root@haiduc"
    $4 = "gasite.txt"
  condition:
    2 of them
}

rule Root_Shell {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "r00t shell"
  condition:
    is_elf and $1
}


rule Blackhole_e1e0 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "e1e03364e6e2360927470ad1b4ba7ea1"
  strings:
    $1 = "This fine tool coded by Bronc Buster"
    $2 = "I_did_not_change_HIDE"
    $3 = "/etc/.pwd.lock"
  condition:
    for any i in (0 .. elf.number_of_segments): (
			hash.md5(elf.segments[i].offset, elf.segments[i].memory_size) == "2ee12c5c21c794cbedfc274751f8218d"
		) or
    all of them
}


rule Koka_27d3 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "27d39d44fc547e97f4e1eb885f00d60e"
  strings:
    $1 = { 68 d6 86 04 08 e8 83 fe ff ff} // execve("/bin/sh")
    $2 = "/dev/mounnt"
    $3 = "cocacola"
  condition:
    all of them
}


rule Orbit_6704 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "67048a69a007c37f8be5d01a95f6a026"
  strings:
    $1 = "sniff_ssh_session"
    $2 = "getpwnam_r"
    $4 = "chown -R 920366:920366"
    $5 = "libntpVnQE6mk"
    $6 = "os.execv(\"/bin/bash\", (\"/bin/bash\", \"-i\"))" base64
    $7 = "os.setreuid(0,0)" base64
    $8 = "lib0UZ0LfvWZ.so"
    $9 = "/dev/shm/ldx/.l"
    $10 = "libntpVnQE6mk"
  condition:
    5 of them
}


rule Orbit_ac89 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "ac89d638cb6912b58de47ac2a274b2fb"
  strings:
    $1 = "HTTP_X_MAGICAL_PONIES"
    $2 = "/dev/shm/.lck"
    $3 = "/tmp/.orbit"
    $4 = "ld.so.nohwcap"
    $5 = "setegid"
  condition:
    3 of them
}
