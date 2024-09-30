import "elf"
import "math"
include "rules/magics.yar"


rule Proc_SelfDeleteBinary {
  // https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
  condition:
    proc_exe endswith " (deleted)" and not proc_exe_exists
}


rule Proc_ThreadMasquerading {
  // https://www.sandflysecurity.com/blog/detecting-linux-kernel-process-masquerading-with-command-line-forensics/
  condition:
    proc_name startswith "[" and proc_name endswith "]" and proc_exe startswith "/"
}


private rule Proc_StdRedirection {
  /*
    Detect file descriptors of a running process that's redirected to a socket connection
    C code could be like: dup2(sockt, 0); dup2(sockt, 1); dup2(sockt, 2);
  */
  condition:
    (
      fd_stdin startswith "socket:[" and fd_stdout startswith "socket:["
    ) or
    (
      fd_stdin == "/dev/pts/2" and fd_stdout == "/dev/pts/2" and fd_stderr == "/dev/pts/2"
    )
}


rule Proc_RevShellNetcat {
  strings:
    $ = "Usage: ncat [options] [hostname] [port]" fullword ascii
    $ = "Proxy-Authenticate: Basic realm=\"Ncat\"" fullword ascii
    $ = "ncat_ssl.c: Invoking ssl_handshake" fullword ascii
    $ = "%s/ncat.XXXXXX" fullword ascii
  condition:
    (
      proc_cmdline contains "-e" or Proc_StdRedirection
    ) and
    (
      (proc_name endswith "ncat" or proc_name endswith "ncat") or // Use process name to detect netcat precisely. Usually inside the system
      2 of them // What if binary's name was changed? Detect using common strings in nc or ncat
    )
}


rule Proc_ReverseShell {
  // Detect Reverse shell that redirects file descriptor to socket
  // TODO need more name
  // FIXME: /proc/*/exe might not be absolute path
  condition:
    for f_name in ("/bash", "/sh", "/zsh", "/dash", "/ash", "/ksh", "/busybox"):
    (
      Proc_StdRedirection and proc_exe endswith f_name
    )
}


rule ELF_AddRootToCrontab {
  strings:
    $ = "* * * * root" fullword ascii
    $ = "/etc/crontab" fullword ascii
  condition:
    elf_magic and all of them
}


rule ELF_ShellcodeExec {
  /*
    Default shellcode loaders on internet will export keyword code or shellcode into symtab (global var only)
    There is a false positive from yara name matching. Condition elf.symtab[i].name == "buf" matched
    any object name contains "buf" like "xxxbuf"
    False positive: /usr/lib/debug/.build-id/2e/5abcee94f3bcbed7bba094f341070a2585a2ba.debug
    False positive /usr/lib/modules/5.16.0-12parrot1-amd64/kernel/drivers/accessibility/speakup/speakup.ko
    */
  condition:
    elf_exec and for any f_sym in elf.symtab:
    (
      for any f_name in ("shellcode", "code"):
      (
        f_sym.type == elf.STT_OBJECT and
        f_sym.name == f_name
      )
    )
}


rule ELF_LoadSegmentRWE {
  /*
    Detect binaries that has LOAD segment that has RWE permission
    reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L3"
    reference = "https://www.tenable.com/blog/hunting-linux-malware-with-yara"
    License: No License detected
  */
  condition:
    elf_magic and for any f_segment in elf.segments:
    (
      f_segment.type == elf.PT_LOAD and
      f_segment.flags == 7 // R+W+X. Sample of Meterpreter has only 1 segment. Need to check for False positive
    )
}


rule PUA_AddUser {
  // meta:
  //   description = "Bash commands to add new user to passwd"
  strings:
    $ = /echo[ "]+[\w\d_]+::0:0::\/:\/bin\/[\w"]+[ >]+\/etc\/passwd/
  condition:
    (elf_magic or shebang_magic) and all of them
}


rule PUA_WgetAndChmod {
  // meta:
  //   description = "Bash commands to download and execute binaries using wget"
  //   reference = "https://www.trendmicro.com/en_us/research/19/d/bashlite-iot-malware-updated-with-mining-and-backdoor-commands-targets-wemo-devices.html"
  strings:
    $ = /wget([ \S])+[; ]+chmod([ \S])+\+x([ \S])+[; ]+.\/(\S)+/
  condition:
    (elf_magic or shebang_magic) and all of them
}


rule PUA_CurlAndChmod {
  // meta:
  //   description = "Bash commands to download and execute binaries using CURL"
  //   refrence = "https://otx.alienvault.com/indicator/file/2557ee8217d6bc7a69956e563e0ed926e11eb9f78e6c0816f6c4bf435cab2c81"
  strings:
    $ = /curl([ \S])+\-O([ \S])+[; ]+cat([ >\.\S])+[; ]+chmod([ \S])+\+x([ \S\*])+[; ]+.\/([\S ])+/
  condition:
    (elf_magic or shebang_magic) and all of them
}


rule PUA_WgetCurlAndChmod {
  // meta:
  //   description = "Bash commands to download and execute binaries using CURL || Wget"
  //   hash = "16bbeec4e23c0dc04c2507ec0d257bf97cfdd025cd86f8faf912cea824b2a5ba"
  //   hash = "b34bb82ef2a0f3d02b93ed069fee717bd1f9ed9832e2d51b0b2642cb0b4f3891"
  strings:
    $ = /wget([ \S])+[; |]+curl([ \S]+)\-O([ \S])+[ |]+[&|; ]+chmod[&|; \d\w\.]+\//
  condition:
    (elf_magic or shebang_magic) and all of them
}

// rule ELF_FakeDynSym {
//   // meta:
//   //   description = "A fake dynamic symbol table has been added to the binary"
//   //   family = "Obfuscation"
//   //   filetype = "ELF"
//   //   hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"
//   //   reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L47"
//   condition:
//     elf_exec and
//     elf.entry_point < filesize and // file scanning only
//     elf.number_of_sections > 0 and
//     elf.dynamic_section_entries > 0 and
//     for any i in (0..elf.dynamic_section_entries):
//     (
//       elf.dynamic[i].type == elf.DT_SYMTAB and
//       not
//       (
//         for any j in (0..elf.number_of_sections):
//         (
//           elf.sections[j].type == elf.SHT_DYNSYM and
//           for any k in (0..elf.number_of_segments):
//           (
//             (elf.segments[k].virtual_address <= elf.dynamic[i].val) and
//             ((elf.segments[k].virtual_address + elf.segments[k].file_size) >= elf.dynamic[i].val) and
//             (elf.segments[k].offset + (elf.dynamic[i].val - elf.segments[k].virtual_address)) == elf.sections[j].offset
//           )
//         )
//       )
//     )
// }

// rule ELF_FakeSectionHdrs {
//   // meta:
//   //   description = "A fake sections header has been added to the binary."
//   //   family = "Obfuscation"
//   //   filetype = "ELF"
//   //   hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"
//   //   reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L17"
//   condition:
//     elf_exec and
//     elf.entry_point < filesize and // file scanning only
//     elf.number_of_segments > 0 and
//     elf.number_of_sections > 0 and
//     not defined elf.symtab_entries and
//     not defined elf.dynsym_entries and not
//     (
//       for any i in (0 .. elf.number_of_segments):
//       (
//         (elf.segments[i].offset <= elf.entry_point) and
//         ((elf.segments[i].offset + elf.segments[i].file_size) >= elf.entry_point) and
//         for any j in (0 .. elf.number_of_sections):
//         (
//           elf.sections[j].offset <= elf.entry_point and
//           ((elf.sections[j].offset + elf.sections[j].size) >= elf.entry_point) and
//           (elf.segments[i].virtual_address + (elf.entry_point - elf.segments[i].offset)) ==
//           (elf.sections[j].address + (elf.entry_point - elf.sections[j].offset))
//         )
//       )
//     )
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

// rule ImportFuncs_Backdoor {
//   // meta:
//   //   descriptions = "Common imports by remote shell. Usually simple reverse tcp"
//     // Doesn't work when scan processes
//     /* Falsee positives
//     SusELF_BackdoorImp /usr/bin//tcpliveplay
//     SusELF_BackdoorImp /usr/bin//tcpprep
//     SusELF_BackdoorImp /usr/bin//tcpbridge
//     SusELF_BackdoorImp /usr/bin//tcpreplay
//     SusELF_BackdoorImp /usr/bin//tcpreplay-edit
//     SusELF_BackdoorImp /usr/bin//tcprewrite
//     */
//   condition:
//     elf_magic and elf.dynsym_entries < 2000 and
//     (
//       for 1 i in (0 .. elf.dynsym_entries):
//       (
//         elf.dynsym[i].type == elf.STT_FUNC and
//         (
//           elf.dynsym[i].name == "execl" or
//           elf.dynsym[i].name == "execve" or
//           elf.dynsym[i].name == "execvle" or
//           elf.dynsym[i].name == "execvp" or
//           elf.dynsym[i].name == "execv" or
//           elf.dynsym[i].name == "execlp" or
//           elf.dynsym[i].name == "system"
//         )
//       )
//     ) and
//     (
//       for 1 i in (0 .. elf.dynsym_entries):
//       (
//         elf.dynsym[i].type == elf.STT_FUNC and
//         (
//           elf.dynsym[i].name == "htons" or
//           elf.dynsym[i].name == "htonl"
//         )
//       )
//     ) and
//     (
//       for 1 i in (0 .. elf.dynsym_entries):
//       (
//         elf.dynsym[i].type == elf.STT_FUNC and
//         (
//           elf.dynsym[i].name == "dup" or
//           elf.dynsym[i].name == "dup2" or
//           elf.dynsym[i].name == "dup3"
//         )
//       )
//     )
// }

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
