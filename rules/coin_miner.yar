import "elf"
import "hash"
include "rules/magics.yar"


rule MineTool_Generic
{
  meta:
    description = "Generic strings in coin miner"
  strings:
    $ = "Memory: %u KiB, Iterations: %u, Parallelism: %u lanes, Tag length: %u bytes" fullword ascii
    $ = "Block %.4u [%3u]: %016lx" fullword ascii
    $ = "Started Mining" fullword ascii
    $ = "Miner will restart" fullword ascii
    $ = "Miner not responding" fullword ascii
    $ = "stratum+ssl://" ascii
    $ = "stratum+tcp://" ascii
    $ = "daemon+https://" ascii
    $ = "daemon+http://" ascii
  condition:
    elf_magic and any of them
}


rule Connecticoin_Generic
{
  meta:
    description = "Generic strings in connection coin"
  strings:
    $1 = "connecticoin.org" fullword ascii nocase
    $2 = "Connecticoin-Qt" fullword ascii
  condition:
    elf_magic and all of them
}


rule XMRStak_Generic {
  meta:
    description = "Generic strings in xml stak"
  strings:
    $1 = "XMRSTAK_VERSION" fullword ascii
    $2 = "pool.usxmrpool.com" fullword ascii nocase
    $3 = "donate.xmr-stak.net" fullword ascii nocase
    $4 = "xmr-stak-rx" fullword ascii
  condition:
    elf_magic and 2 of them
}


rule Xmrig_Generic
{
  meta:
    descriptions = "Generic strings in xmrig"
  strings:
    $1 = "xmrig.com" fullword ascii nocase
    $2 = "cryptonight" fullword ascii
    $3 = "_ZN5xmrig" ascii
    $4 = "Usage: xmrig [OPTIONS]" ascii
    $5 = "xmrig.json" fullword ascii
    $6 = "xmrigMiner" fullword ascii
    $7 = "jcxmrig" ascii
    $8 = "xmrigvertar" ascii
  condition:
    elf_magic and 3 of them
}


rule NBMiner_682e {
  meta:
    hash = "682e9645f289292b12561c3da62a059b"
    reference = "https://www.virustotal.com/gui/file/a819b4a95f386ae3bd8f0edc64e8e10fae0c21c9ae713b73dfc64033e5a845a1?nocache=1"
  strings:
    $1 = "/mnt/d/code/NBMiner"
    $2 = "_ZN5Miner10signalStopEv"
  condition:
    elf_magic and any of them
}

rule GoMiner_b238 {
  meta:
    description = "A heavily striped Golang coin miner"
    md5 = "b238fe09791e169600fd3dbcdd0018a3"
  strings:
    $ = "Zpw9qKOmhDOzF3GWwJTB"
  condition:
    elf_magic and any of them
}
