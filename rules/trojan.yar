import "elf"
import "hash"
include "commons.yar"


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

rule Heur_Shellcode_Executor
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Try to detect shellcode executor by exported \"shellcode\" string"
  condition:
    is_elf and for any i in (0 .. elf.symtab_entries - 1): (
      (elf.symtab[i].name == "shellcode" or elf.symtab[i].name == "code") and elf.symtab[i].type == elf.STT_OBJECT
    )
}


rule Trojan_Python_IRCBot
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

rule Trojan_GoLang_EzuriLoader
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Trojan written in Golang. https://www.virustotal.com/gui/file/751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "dfd54f22d3a3bb072d34c424aa554500"
    )
}

rule custom_ssh_backdoor_server {
	meta:
		description = "Custome SSH backdoor based on python and paramiko - file server.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth"
		reference = "https://goo.gl/S46L3o"
		date = "2015-05-14"
		hash = "0953b6c2181249b94282ca5736471f85d80d41c9"
	strings:
		$s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
		$s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
		$s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
		$s3 = "chan.send(command)" fullword ascii
		$s4 = "print '[-] SSH negotiation failed.'" fullword ascii
		$s5 = "except paramiko.SSHException, x:" fullword ascii
	condition:
		filesize < 10KB and 5 of them
}