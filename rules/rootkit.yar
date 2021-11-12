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
