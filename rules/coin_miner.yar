import "elf"
import "hash"
include "rules/magics.yar"


rule MineTool_Generic
{
  // meta:
  //   description = "Generic strings in coin miner"
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
  // meta:
  //   description = "Generic strings in connection coin"
  strings:
    $ = "connecticoin.org" fullword ascii nocase
    $ = "Connecticoin-Qt" fullword ascii
  condition:
    elf_magic and all of them
}


rule XMRStak_Generic {
  // meta:
  //   description = "Generic strings in xml stak"
  strings:
    $ = "XMRSTAK_VERSION" fullword ascii
    $ = "pool.usxmrpool.com" fullword ascii nocase
    $ = "donate.xmr-stak.net" fullword ascii nocase
    $ = "xmr-stak-rx" fullword ascii
  condition:
    elf_magic and 2 of them
}


rule Xmrig_Generic
{
  meta:
    descriptions = "Generic strings in xmrig"
  strings:
    $ = "xmrig.com" fullword ascii nocase
    $ = "cryptonight" fullword ascii
    $ = "_ZN5xmrig" ascii
    $ = "Usage: xmrig [OPTIONS]" ascii
    $ = "xmrig.json" fullword ascii
    $ = "xmrigMiner" fullword ascii
    $ = "jcxmrig" ascii
    $ = "xmrigvertar" ascii
  condition:
    elf_magic and 3 of them
}


rule NBMiner_682e {
  meta:
    hash = "682e9645f289292b12561c3da62a059b"
    reference = "https://www.virustotal.com/gui/file/a819b4a95f386ae3bd8f0edc64e8e10fae0c21c9ae713b73dfc64033e5a845a1?nocache=1"
  strings:
    $ = "/mnt/d/code/NBMiner"
    $ = "_ZN5Miner10signalStopEv"
  condition:
    elf_magic and any of them
}

rule GoMiner_b238 {
  // meta:
  //   description = "A heavily striped Golang coin miner"
  //   md5 = "b238fe09791e169600fd3dbcdd0018a3"
  strings:
    $ = "Zpw9qKOmhDOzF3GWwJTB"
  condition:
    elf_magic and any of them
}


rule Ddgs_d618 {
  // meta:
  //   info = "VirusShare_d6187a44abacfb8f167584668e02c918"
  //   md5 = "VirusShare_d6187a44abacfb8f167584668e02c918"
  strings:
    $ = "miner.go" fullword ascii
    $ = "backdoor.go" fullword ascii
    $ = "(*backdoor)" fullword ascii
    $ = "(*miner" ascii
  condition:
    elf_magic and 2 of them
}
