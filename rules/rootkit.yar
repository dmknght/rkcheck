include "rules/commons.yar"


rule HCRootkit_1_LaceworkLabs {
  meta:
    description = "Detects Linux HCRootkit, as reported by Avast"
    hash1 = "2daa5503b7f068ac471330869ccfb1ae617538fecaea69fd6c488d57929f8279"
    hash2 = "10c7e04d12647107e7abf29ae612c1d0e76a79447e03393fa8a44f8a164b723d"
    hash3 = "602c435834d796943b1e547316c18a9a64c68f032985e7a5a763339d82598915"
    author = "Lacework Labs"
    ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
  strings:
    $a1 = "172.96.231."
    $a2 = "/tmp/.tmp_XXXXXX"
    $s1 = "/proc/net/tcp"
    $s2 = "/proc/.inl"
    $s3 = "rootkit"
  condition:
    is_elf and 
      ((any of ($a*)) and (any of ($s*)))
}

rule HCRootkit_2_LaceworkLabs {
  meta:
    description = "Detects Linux HCRootkit Wide, unpacked"
    hash1 = "2daa5503b7f068ac471330869ccfb1ae617538fecaea69fd6c488d57929f8279"
    hash2 = "10c7e04d12647107e7abf29ae612c1d0e76a79447e03393fa8a44f8a164b723d"
    author = "Lacework Labs"
    ref = "https://www.lacework.com/blog/hcrootkit-sutersu-linux-rootkit-analysis/"
  strings:
    $s1 = "s_hide_pids"
    $s2 = "handler_kallsyms_lookup_name"
    $s3 = "s_proc_ino"
    $s4 = "n_filldir"
    $s5 = "s_is_proc_ino"
    $s6 = "n_tcp4_seq_show"
    $s7 = "r_tcp4_seq_show"
    $s8 = "s_hide_tcp4_ports"
    $s9 = "s_proc_open"
    $s10 = "s_proc_show"
    $s11 = "s_passwd_buf"
    $s12 = "s_passwd_buf_len"
    $s13 = "r_sys_write"
    $s14 = "r_sys_mmap"
    $s15 = "r_sys_munmap"
    $s16 = "s_hide_strs"
    $s17 = "s_proc_write"
    $s18 = "s_proc_inl_operations"
    $s19 = "s_inl_entry"
    $s20 = "kp_kallsyms_lookup_name"
    $s21 = "s_sys_call_table"
    $s22 = "kp_do_exit"
    $s23 = "r_sys_getdents"
    $s24 = "s_hook_remote_ip"
    $s25= "s_hook_remote_port"
    $s26 = "s_hook_local_port"
    $s27 = "s_hook_local_ip"
    $s28 = "nf_hook_pre_routing"
  condition:
    is_elf and 10 of them
}

rule Suterusu_LaceworkLabs {
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
    is_elf and all of them
}

rule Umbreon_TrendMicro {
	meta:
		description = "Catches Umbreon rootkit"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"
	
	strings:
		$ = { 75 6e 66 75 63 6b 5f 6c 69 6e 6b 6d 61 70 }
		$ = "unhide.rb" ascii fullword
		$ = "rkit" ascii fullword

	condition:
		is_elf // Generic ELF header
		and uint8(16) == 0x0003 // Shared object file
		and all of them
}

rule Umbreon_strace_TrendMicro {
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
		is_elf // Generic ELF header
		and uint8(16) == 0x0003 // Shared object file
		and all of them
}

rule Umbreon_espeon_TrendMicro {
	meta:
		description = "Catches Umbreon strace rootkit component"
		reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/pokemon-themed-umbreon-linux-rootkit-hits-x86-arm-systems"
		author = "Fernando Merces, FTR, Trend Micro"
		date = "2016-08"

	strings:
		$ = "Usage: %s [interface]" fullword
		$ = "Options:" fullword
		$ = "    interface    Listen on <interface> for packets." fullword
		$ = "/bin/espeon-shell %s %hu"
		$ = { 66 75 63 6b 20 6f 66 66 20 63 75 6e 74 }
		$ = "error: unrecognized command-line options" fullword

	condition:
		is_elf // Generic ELF header
		and uint8(16) == 0x0002 // Executable file
		and all of them
}

rule Knark {
  meta:
		author = "Nong Hoang Tu <dmknght@parrotsec.org>"
		date = "17/11/2021"
	strings:
		$path_1 = "/usr/lib/.hax0r/sshd_trojan"
    $path_2 = "/usr/local/sbin/sshd"
    $path_3 = "/usr/lib/.hax0r"
    $cmd_1 = "hidef"
    $cmd_2 = "unhidef"
    $cmd_3 = "nethides"
    $cmd_4 = "verify_rexec"
    $s1 = "Knark rexec verify-packet must be one of:"
    $s2 = "nark %s by Creed @"
    $s3 = "fikadags?"
    $s4 = "%s -c (clear nethide-list)"
    $s5 = "ex: %s www.microsoft.com 192.168.1.77 /bin/rm -fr /"
    $s6 = "Have you really loaded knark.o?!"
    $s7 = "alluid or allgid can be used to specify all *uid's or *gid's"
	condition:
		any of ($s*) or (
      any of ($path*) and any of ($cmd*)
    )
}

rule Ark_ar {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "06d8660ace1f3ef557a7df2e85623cce"
  strings:
    $1 = "Mmmkay.. Time to backdoor thiz slut.."
    $2 = "Backdooring Completed"
    $3 = "ARK-[ You may want to supply a password"
    $4 = "ARK-[ Welcome to ARK"
  condition:
    any of them
}

rule Ark_du {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "58f6c91ca922aa3d6f6b79b218e62b46"
  strings:
    $path_1 = "/usr/lib/.ark"
    $s1 = "ptyxx"
    $s2 = "SUBJECT: `/sbin/ifconfig eth0 | grep 'inet addr' | awk '{print $2}' | sed -e 's/.*://'`"
    $mail_1 = "tuiqoitu039t09q3@bigfoot.com"
    $mail_2 = "bnadfjg9023@hotmail.com"
    $mail_3 = "t391u9t0qit@end-war.com"
    $mail_4 = "mki62969o@yahoo.com"
  condition:
    (is_elf and $path_1 and $s1) or $s2 or any of ($mail*)
}

rule Lrk_B_fix {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "a29f6927825c948c5df847505fe2dd11"
  strings:
    $1 = "fix original replacement [backup]"
    $2 = "fix: Last 17 bytes not zero"
    $3 = "fix: Can't fix checksum"
  condition:
    all of them
}

rule Lrk_B_lled {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "bf10ff4214716f20bcd23227c6b6c0bb"
  strings:
    $1 = "/var/adm/lastlog"
    $2 = "lastlog.tmp"
    $3 = "Erase entry (y/n/f(astforward))?"
    $4 = "/var/adm/wtmp"
    $5 = "wtmp.tmp"
  condition:
    ($1 and $2) or ($4 and $5) and $3
}

rule Lrk_B_z2 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "0181b03af8360480baf346007ec76849"
  strings:
    $1 = "/etc/utmp"
    $2 = "/usr/adm/wtmp"
    $3 = "/usr/adm/lastlog"
    $4 = /Zap[\d]/
  condition:
    all of them
}

rule Lrk_E_sniffchk {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "82a61d8b23956703f164b06968a8e599"
  strings:
    $1 = "The_l0gz"
    // $2 = "/var/run/.tmp"
    $3 = "Sniffer running"
    $4 = "Restarting sniffer..."
  condition:
    any of them
}

rule Lrk_E_bindhshell {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
    hash = "96702b7180082a00b2ced1a243360ed6"
  strings:
    $1 = "(nfsiod)"
    $2 = "/bin/sh"
  condition:
    all of them
}

rule Rkit_a {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "rootkit() failed!"
    $2 = "password guesses exhausted"
    $3 = "rkit by Deathr0w"
    $4 = "deathr0w.speckz.com"
  condition:
    any of them
}

rule Rkit_pwd {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "./.rkpass"
    $2 = "Enter a new password [1-8 characters]"
    $3 = "Writing to file: %s failed! Exiting..."
    $4 = "Opening of file: %s failed! Exiting..."
    $5 = "Saved new password to file: %"
  condition:
    (is_elf and $1) or ($2 and $3 and $4 and $5)
}

rule Suckit_b {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "FUCK: Can't allocate raw socket"
    $2 = "FUCK: Can't fork child"
    $3 = "BD_Init: Starting backdoor daemon..."
    $4 = "Suckit uninstalled sucesfully!"
    $5 = "Please enter new rootkit password:"
  condition:
    any of them
}

rule Urk {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "Inverses the bit's in a file to make it unreadable."
    $2 = "@(#)log"
    $3 = " (Berkeley) "
    $4 = "UX:login: ERROR: Login incorrect"
    $5 = "User %s (gid %d) from %s: %s"
  condition:
    any of them
}
