import "elf"
import "hash"
include "rules/magics.yar"


rule Shellcode_9db6 {
  // meta:
  //   descriptions = "A shellcode executor"
  //   md5 = "9db6918b94456e4f7fc981b5e3cf289e"
  strings:
    // Value in shellcode
    $ = "kl q60?"
    $ = "&'Qm"
  condition:
    elf_exec and all of them
}


rule SSHD_95d7 {
  // meta:
  //   description = "SSH Backdoor"
  //   md5 = "95d7335fa643949534f128795c8ac21c"
  strings:
    $ = "Rhosts Authentication disabled, originating port %d not trusted." ascii
    $ = "kHgn4vlwonyP" fullword ascii
  condition:
    elf_magic and all of them
}


rule Infector_849b {
  // meta:
  //   md5 = "849b45fee92762d2b6ec31a11e1bcd76"
  //   description = "A Nim infector malware"
  strings:
    $1 = "akpcTVEZHXJe8ZbbQdHsSA" // Contains in strtab. Static binary only
    // 2 strings should show at runtime.
    $2 = "/tmp/.host"
    $3 = "The more you know... :)"
  condition:
    elf_exec and (
      for any i in (0 .. elf.number_of_sections):
      (
        $1 in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      2 of them
    )
}


rule Agent_be4d {
  // meta:
  //   md5 = "be4d3133afee0f4da853430339ba379f"
  strings:
    $ = "/tmp/.server.sig" fullword ascii
    $ = "touch /tmp/elevate" fullword ascii
    $ = "/c.php?authkey=" fullword ascii
  condition:
    elf_magic and any of them
}


rule Kowai_f06a {
  // meta:
  //   md5 = "f06a780e653c680e2e4ddab4b397ddd2"
  strings:
    $ = "KOWAI-BAdAsV" fullword ascii
    $ = "KOWAI-d" fullword ascii
  condition:
    elf_magic and any of them
}


rule ShellCmd_UserAdd {
  // meta:
  //   description = "Bash commands to add new user to passwd"
  strings:
    $ = /echo[ "]+[\w\d_]+::0:0::\/:\/bin\/[\w"]+[ >]+\/etc\/passwd/
  condition:
    (elf_magic or shebang_magic) and all of them
}

rule Dropper_Wget {
  // meta:
  //   description = "Bash commands to download and execute binaries using wget"
  //   reference = "https://www.trendmicro.com/en_us/research/19/d/bashlite-iot-malware-updated-with-mining-and-backdoor-commands-targets-wemo-devices.html"
  strings:
    $ = /wget([ \S])+[; ]+chmod([ \S])+\+x([ \S])+[; ]+.\/(\S)+/
  condition:
    (elf_magic or shebang_magic) and all of them
}

rule Dropper_Curl {
  // meta:
  //   description = "Bash commands to download and execute binaries using CURL"
  //   refrence = "https://otx.alienvault.com/indicator/file/2557ee8217d6bc7a69956e563e0ed926e11eb9f78e6c0816f6c4bf435cab2c81"
  strings:
    $ = /curl([ \S])+\-O([ \S])+[; ]+cat([ >\.\S])+[; ]+chmod([ \S])+\+x([ \S\*])+[; ]+.\/([\S ])+/
  condition:
    (elf_magic or shebang_magic) and all of them
}

rule Dropper_WgetCurl {
  // meta:
  //   description = "Bash commands to download and execute binaries using CURL || Wget"
  //   hash = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
  //   hash = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
  strings:
    $ = /wget([ \S])+[; |]+curl([ \S]+)\-O([ \S])+[ |]+[&|; ]+chmod[&|; \d\w\.]+\//
  condition:
    (elf_magic or shebang_magic) and all of them
}


rule PortScan_TypeA {
  // meta:
  //   hash = "946689ba1b22d457be06d95731fcbcac"
  strings:
    $ = "[i] Scanning:" fullword ascii
    $ = "Usage: %s <b-block> <port> [c-block]" fullword ascii
    $ = "Portscan completed in" fullword ascii
  condition:
    elf_magic and 2 of them
}

rule PortScan_TypeB {
  // meta:
  //   hash = "946689ba1b22d457be06d95731fcbcac"
  strings:
    $ = "FOUND: %s with port %s open" fullword ascii
    $ = "%s:%s %s port: %s --> %s" fullword ascii
  condition:
    elf_magic and 2 of them
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

// rule EzuriLoader_Generic
// {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Detect file by section hash for EzuriLoader's Golang binaries"
//     reference = "https://www.virustotal.com/gui/file/751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
//     hash = "751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
//   condition:
//     is_elf and hash.md5(elf.sections[3].offset, elf.sections[3].size) == "dfd54f22d3a3bb072d34c424aa554500"
// }


rule Meter_Stageless {
  // meta:
  //   description = "Metasploit's stageless payload (no encoders)"
  strings:
    $ = "MSF_LICENSE" fullword ascii
    $ = "mettle_get_procmgr" fullword ascii
  condition:
    elf_magic and any of them
}


rule Meter_RevTCP {
  // meta:
  //   description = "Metasploit staged payload (no encoders)"
  strings:
    $ = "AYPj)X" fullword ascii
    $ = "Wj#Xj" fullword ascii
  condition:
    elf_magic and all of them
}


rule Excedoor_Generic {
  // meta:
  //   description = "Linux Excedoor"
  //   refrence = "https://otx.alienvault.com/indicator/file/6138054a7de11c23b5c26755d7548c4096fa547cbb964ac78ef0fbe59d16c2da"
  //   hash = "3d06f85ac19dc1a6f678aa4e28ce5c42"
  strings:
    $ = "/bin/sh" fullword ascii
    $ = "rm -rf /var/log/*" fullword ascii
    $ = "Brand new TCP root shell!" fullword ascii
  condition:
    elf_exec and all of them
}

rule Explodor_Generic {
  // meta:
  //   description = "Generic rule for a backdoor that spawns shell and shellcode. Shared string with explodor"
  //   url = "https://otx.alienvault.com/indicator/file/fb5eba7a927ce0513e11cde7a496009453f2d57b72c73fcbe04e9a527a3eabac"
  strings:
    $ = "Unable to write shellcode" fullword ascii
    $ = "Shellcode placed at" fullword ascii
    $ = "Now wait for suid shell" fullword ascii
    $ = "Unable to spawn shell" fullword ascii
  condition:
    elf_exec and any of them
}

rule EarthWorm_Generic {
  // meta:
  //   description = "Earthworm backdoor"
  strings:
    $ = "rootkiter" fullword ascii nocase
    $ = "darksn0w" fullword ascii
    $ = "zhuanjia" fullword ascii
    $ = "syc4mor3" fullword ascii
    $ = "Wooyaa" fullword ascii
    $ = "init cmd_server_for_rc here" fullword ascii
  condition:
    elf_exec and 3 of them
}

// TODO hunt from https://www.hybrid-analysis.com/yara-search/results/e0f6fc9e4611bbff2192b250951d22a73180966f58c2c38e98d48f988246a2e5
// hunted strings: hlLjztqZ and npxXoudifFeEgGaACScs format of some libs

// rule EkoBackdoor_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux EkoBackdoor"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/74d29efbdf7df9bb7e51fad039e0e40455795056ec643610b38853c602a4357c"
//     target = "File, memory"
//   strings:
//     $spec_1 = "Backdoor instalado! - Have a nice hack ;)"
//     $spec_2 = "Coded by ca0s / Ezkracho Team >"
//     $spec_3 = "EkoBackdoor v1.1 by ca0s"
//     $spec_4 = "ekorulez"
//     $spec_5 = "stream tcp nowait root /bin/sh sh -i"
//     $cmd_2 = "cp /bin/sh /tmp/sh"
//     $cmd_3 = "chmod 4711 /tmp/sh"
//     $cmd_4 = "./ekobdoor"
//   condition:
//     any of ($spec_*) or all of ($cmd_*)
// }


// rule Homeunix_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux Homeunix"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/ced749fecb0f9dde9355ee29007ea8a20de277d39ebcb5dda61cd290cd5dbc02"
//     target = "File, memory"
//   strings:
//     $s1 = "unixforce::0:0:unixforce:/root:/bin/bash"
//     $s2 = "/etc/passwd"
//   condition:
//     all of them
// }

// rule Fysbis_364f {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux Fysbis"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/ab6f39f913a925cf4e9fa7717db0e3eb38b5ae61e057a2e76043b539f3c0dc91"
//     reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
//     reference = "https://github.com/Yara-Rules/rules/blob/master/malware/APT_Sofacy_Fysbis.yar"
//     reference = "https://www.hybrid-analysis.com/sample/8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
//     target = "File, memory"
//     hash = "364ff454dcf00420cff13a57bcb78467"
//   strings:
//     $addr_1 = "azureon-line.com" nocase
//     $path_1 = ".config/dbus-notifier" // full path: .config/dbus-notifier/dbus-inotifier
//     $path_2 = ".local/cva-ssys"
//     $path_3 = "~/.config/autostart"
//     $cmd_1 = "rm -f ~/.config/autostart/"
//     $cmd_2 = "rm -f /usr/lib/systemd/system/"
//     $cmd_3 = "mkdir /usr/lib/cva-ssys"
//     $cmd_4 = "mkdir ~/.config/autostart" // Could be false positive
//     // Generated when malware is executed as sudo. This is the systemd unit
//     $entry_1 = "ExecStart=/bin/rsyncd"
//     $entry_2 = "Description= synchronize and backup service"
//   condition:
//     /*
//     This rule works for dump file from gcore. It doesn't work for memory scan
//     for any i in (0 .. elf.number_of_segments): (
//       4 of ($path_*, $cmd_*, $addr_*) in (elf.segments[i].offset .. elf.segments[i].offset + elf.segments[i].file_size)
//     )
//     */
//     (is_elf and for any i in (0 .. elf.number_of_sections - 1): (
//       elf.sections[i].name == ".rodata" and
//       4 of ($path_*, $cmd_*, $addr_*) in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
//     )) or
//     (4 of ($path_*, $cmd_*, $addr_*) in (0x418d00 .. 0x41a4ff)) or // Memory scan
//     ($path_1 and xdg_desktop_entry) or // desktop file, startup as user
//     ($entry_1 and $entry_2) // systemd unit, startup as root
// }

// rule Gbkdoor_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux Gbkdoor"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/a1439937c8a383f010a071130aaae4443de6b7f4f7e71789c9964ea3a9d7f4a8"
//     target = "File, memory"
//   strings:
//     $1 = "mmeneghin@inwind.it"
//     $2 = "as if you are root, but the file to trojanize must be suidroot!"
//     $3 = "now, you can easily use the backdoor installed so:"
//   condition:
//     $1 or ($2 and $3)
// }

// rule Gummo_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux Gummo"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/67b9ddd4a21a78ff1a4adbf4b2fb70d279c79494d34e6e2e12673eed134f0d5f"
//     target = "File, memory"
//   strings:
//     $ = "echo rewt::0:0::/:/bin/sh>>/etc/passwd;"
//   condition:
//     all of them
// }

// rule KBD_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Linux KBD"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/3aba59e8bbaecf065d05b7a74655668484bb16fdec589b8e7d169e4adf65d840"
//     target = "File, memory"
//   strings:
//     $1 = "Your Kung-Fu is good."
//     $2 = "orig_stat"
//     $3 = "bd_getuid"
//     $4 = "orig_getuid"
//   condition:
//     all of them
// }


// rule BashDoor_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "13/11/2021"
//     target = "File, memory"
//   strings:
//     $1 = "SeCshell" nocase
//     $2 = "Update and backdoor"
//     $3 = "bash"
//     $4 = "nU.ajj1cF2Qk6"
//   condition:
//     2 of them
// }

// rule MushDoor_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "13/11/2021"
//     target = "File, memory"
//   strings:
//     $1 = "mushd00r"
//     $2 = "username to hide"
//   condition:
//     all of them
// }

// rule IcmpBackdoor_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "icmp-backdoor"
//     $2 = "you need to be root!"
//   condition:
//     all of them
// }

// rule Lyceum_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $ = "d:D:s:S:l:p:P:u:x:i:b:I"
//     $ = "icmp moonbouce backdoor"
//     $ = "bi-spoofed icmp backdoor"
//     $ = "spoof all packets"
//   condition:
//     any of them
// }

// rule Silencer_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = /backdoor[d]_BEGIN/
//     $2 = "ready for injection.."
//     $3 = "0x4553-Silencer"
//     $4 = "by BrainStorm and Ares"
//   condition:
//     any of them
// }

// rule Sneaky_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "i:l:t:s:S:d:D:"
//     $2 = "[Sneaky@%s]#"
//     $3 = "Phish@mindless.com"
//   condition:
//     any of them
// }

// rule Galore_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "Backdoor Galore By NTFX"
//   condition:
//     any of them
// }

// rule BlueDragon_sfe {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "tHE rECIdjVO"
//     $2 = "<recidjvo@pkcrew.org>"
//   condition:
//     any of them
// }

// rule Rrs_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $ = "hlp:b:r:R:t:Dqk:x:sS:P:c:v:C:e:m0LV"
//   condition:
//     any of them
// }

// rule Necro_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $ = "N3Cr0m0rPh"
//   condition:
//     any of them
// }

// rule PunBB_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $ = "change_email SQL injection exploit"
//     $ = "PunBB"
//   condition:
//     all of them
// }

rule Keylog_Xspy {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    descriptions = "Rule to detect X11 Keylogger"
    // Yara failed to detect running process because it can't load elf information such as elf.type
  strings:
    $ = "DISPLAY" fullword ascii
    $ = "for snoopng" fullword ascii
  condition:
    elf_magic and all of them
}


rule Exploit_DirtyCow {
  // meta:
  //   hash = "0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
  //   reference = "https://www.virustotal.com/gui/file/0b22cdc1b1b1f944e4ca8fced2e234d14aeeef830970e8ae7491cbdcb3e11460"
  strings:
    $ = "/tmp/passwd.bak" ascii
    $ = "madvise %d" fullword ascii
    $ = "ptrace %d" fullword ascii
    $ = "DON'T FORGET TO RESTORE!" ascii
  condition:
    elf.type == elf.ET_EXEC and
    (
      for 6 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and (
          elf.dynsym[i].name == "crypt" or
          elf.dynsym[i].name == "madvise" or
          elf.dynsym[i].name == "ptrace" or
          elf.dynsym[i].name == "waitpid" or
          elf.dynsym[i].name == "getpass" or
          elf.dynsym[i].name == "pthread_create"
        )
      ) or
      all of them
    )
}

// TODO 1384790107a5f200cab9593a39d1c80136762b58d22d9b3f081c91d99e5d0376 (upx)
// hash unpacked: afb6ec634639a68624c052d083bbe28a0076cd3ab3d9a276c4b90cb4163b8317 golang malware
// TODO 139b09543494ead859b857961d230a39b9f4fc730f81cf8445b6d83bacf67f3d: malware downloader rule34 python compiled file

rule TinyShell {
  // meta:
  //   description = "Open-source TinyShell backdoor"
  //   reference = "https://github.com/creaktive/tsh"
    // execl, setsid is in imports, type: func
  strings:
    $ = "s:p:c::" // getopt strings
    $ = "Usage: %s [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]" // Usage
  condition:
    elf_magic and all of them
}


// rule STEELCORGI_packed {
//   meta:
//     description = "Yara Rule for packed ELF backdoor of UNC1945"
//     author = "Yoroi Malware Zlab"
//     last_updated = "2020_12_21"
//     tlp = "white"
//     category = "informational"
//     reference = "https://yoroi.company/research/opening-steelcorgi-a-sophisticated-apt-swiss-army-knife/"
//   strings:
//     $s1 = {4? 88 47 3c c1 6c ?4 34 08 8a 54 ?? ?? 4? 88 57 3d c1 6c}
//     $s2 = {0f b6 5? ?? 0f b6 4? ?? 4? c1 e2 18 4? c1 e0 10 4? }
//     $s3 = {8a 03 84 c0 74 ?? 3c 3d 75 ?? 3c 3d 75 ?? c6 03 00 4? 8b 7d 00}
//     $s4 = {01 c6 89 44 ?? ?? 8b 44 ?? ?? 31 f2 89 74 ?? ?? c1}
//     $s5 = { 4? 89 d8 4? 31 f2 4? c1 e0 13 4? 01 d7 4? }
//   condition:
//     elf_magic and 3 of them
// }


// rule STEELCORGI_generic{
//   meta:
//     description = "Yara Rule for unpacked ELF backdoor of UNC1945"
//     author = "Yoroi Malware Zlab"
//     last_updated = "2020_12_21"
//     tlp = "white"
//     category = "informational"
//     reference = "https://yoroi.company/research/opening-steelcorgi-a-sophisticated-apt-swiss-army-knife/"
//   strings:
//     $s1 = "MCARC"
//     $s2 = "833fc0088ea41bc3331db60ae2.debug"
//     $s3 = "PORA1022"
//     $s4 = "server"
//     $s5 = "test"
//     $s6 = "no ejecutar git-update-server-info"
//     $s7 = "dlopen"
//     $s8 = "dlsym"
//     $s9 = "5d5c6da19e62263f67ca63f8bedeb6.debug"
//     $s10 = {72 69 6E 74 20 22 5B 56 5D 20 41 74 74 65 6D 70 74 69 6E 67 20 74 6F 20 67 65 74 20 4F 53 20 69 6E 66 6F 20 77 69 74 68 20 63 6F 6D 6D 61 6E 64 3A 20 24 63 6F 6D 6D 61 6E 64 5C 6E 22 20 69 66 20 24 76 65 72 62 6F 73 65 3B}

//   condition:
//     elf_magic and
//     (
//       for any i in (0 .. elf.number_of_sections):
//       (
//         all of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size) and #s4 > 50 and #s5 > 20
//       ) or
//       for any i in (0 .. elf.number_of_segments):
//       (
//         all of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size) and #s4 > 50 and #s5 > 20
//       )
//     )
// }

rule Gasit_ada7 {
  // meta:
  //   hash = "946689ba1b22d457be06d95731fcbcac"
  //   url = "https://www.hybrid-analysis.com/sample/f4588a114fa72bb3aa7e20cecdac73e3897911605bcc2ec1e894a87bb99c3ff5/61b1afd8d77a530aae03b1fe"
  //   url = "https://www.hybrid-analysis.com/sample/bcc096e218a3dd87c2bb3fab2d31a19121e8614983bd22b7d6741e5d27e4c119/612f215531b5af1d930f1d6c"
  strings:
    $ = "halucin0g3n" fullword ascii
    $ = "root@haiduc" fullword ascii
    $ = "USER: %s PASS: %s HOST: %s PORT: %s --> %s" fullword ascii
  condition:
    elf_magic and any of them
}

// rule Root_Shell {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "r00t shell"
//   condition:
//     is_elf and $1
// }


// rule Blackhole_e1e0 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     hash = "e1e03364e6e2360927470ad1b4ba7ea1"
//   strings:
//     $1 = "This fine tool coded by Bronc Buster"
//     $2 = "I_did_not_change_HIDE"
//     $3 = "/etc/.pwd.lock"
//   condition:
//     for any i in (0 .. elf.number_of_segments): (
// 			hash.md5(elf.segments[i].offset, elf.segments[i].memory_size) == "2ee12c5c21c794cbedfc274751f8218d"
// 		) or
//     all of them
// }


// rule Koka_27d3 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     hash = "27d39d44fc547e97f4e1eb885f00d60e"
//   strings:
//     $1 = { 68 d6 86 04 08 e8 83 fe ff ff} // execve("/bin/sh")
//     $2 = "/dev/mounnt"
//     $3 = "cocacola"
//   condition:
//     all of them
// }


// rule Orbit_6704 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     hash = "67048a69a007c37f8be5d01a95f6a026"
//   strings:
//     $1 = "sniff_ssh_session"
//     $2 = "getpwnam_r"
//     $4 = "chown -R 920366:920366"
//     $5 = "libntpVnQE6mk"
//     $6 = "os.execv(\"/bin/bash\", (\"/bin/bash\", \"-i\"))" base64
//     $7 = "os.setreuid(0,0)" base64
//     $8 = "lib0UZ0LfvWZ.so"
//     $9 = "/dev/shm/ldx/.l"
//     $10 = "libntpVnQE6mk"
//   condition:
//     5 of them
// }


rule Meter_OleFile {
  // meta:
  //   descriptions = "Generic signature for exploit/multi/misc/openoffice_document_macro"
  strings:
    $ = "Sub Exploit" fullword ascii
    $ = "python -c" fullword ascii
    $ = "exec(r.read())" fullword ascii
  condition:
    xml_magic and all of them
}


rule Lightning_Downloader {
  // meta:
  //   description = "Downloader of lightning framework"
  //   md5 = "204728fb1878b9f4f83c110e7cf6b5b5"
  //   sha256 = "48f9471c20316b295704e6f8feb2196dd619799edec5835734fc24051f45c5b7"
  //   url = "https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/"
  strings:
    $ = "kkdmflush" fullword ascii
    $ = "sleep 60 && ./%s &" fullword ascii
    $ = "TCPvfA" ascii
    $ = "UH-`0a" fullword ascii
  condition:
    elf_exec and 2 of them
}


rule Exploit_NsSploit {
  // meta:
  //   url = "https://www.hybrid-analysis.com/sample/6ffbe23565bbd34805d3dc4364110bb9d6d733107f8f02d0cfd38859ab013cf8"
  strings:
    $ = "ofs-lib.so" fullword ascii
    $ = "/tmp/ns_sploit" fullword ascii
    $ = "cve_2015_1328_binary.c" fullword ascii
    $ = "e10adc3949ba59abbe56e057f20f883e" fullword ascii
  condition:
    elf_exec and 2 of them
}
