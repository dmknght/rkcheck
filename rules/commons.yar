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
