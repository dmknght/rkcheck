import "elf"
import "hash"
include "rules/magics.yar"


rule Coin_Miner_1
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detected Multios.Coinminer.Miner-6781728-2 (ClamAV)"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      elf.sections[i].name == ".comment" and hash.md5(elf.sections[i].offset, elf.sections[i].size) == "d2c0aaec378884e0d4eef2d3bb1db8fc"
    )
}


rule Coin_Miner_2
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "XMRMiner"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "15c48a37f52d016088f1bef13996d4cf"
    )
}

rule Coin_Miner_3
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Generic Coin miner"
    // python coin miner
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "853dd334799573dd41e80091e65fb960"
    )
}

rule Coin_Miner_4
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Generic Coin Miner"
    // other golang coin miner
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "ea5f61d48cc64bcba47ed3d75ccc3e59"
    )
}


rule Connecticoin_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "connecticoin.org"
    $2 = "Connecticoin-Qt"
  condition:
    is_elf and any of them
    // is_elf and for any i in (0 .. elf.number_of_sections - 1): (
    //   elf.sections[i].name == ".rodata" and
    //     $1 in (elf.sections[i].offset .. elf.sections[i + 1].offset) and
    //     $2 in (elf.sections[i].offset .. elf.sections[i + 1].offset)
    // )
}

rule XMRStak_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
  strings:
    $1 = "XMRSTAK_VERSION"
    $2 = "pool.usxmrpool.com"
    $3 = "donate.xmr-stak.net"
    $4 = "xmr-stak-rx 1.0.4-rx 65ade74"
    $5 = "XMRSTAK_VERSION"
  condition:
    is_elf and any of them
}

rule Xmrig_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    // $1 = "donate.v2.xmrig.com"
    $1 = "xmrig.com"
    $2 = "cryptonight/0"
    $3 = "cryptonight-monerov7"
    $4 = "_ZN5xmrig"
    // $5 = "miner.fee.xmrig.com"
    // $6 = "emergency.fee.xmrig.com"
    $7 = "Usage: xmrig [OPTIONS]"
    $8 = "xmrig.json"
    $9 = "xmrigMiner" // fixme can't detect 0a79399*
  condition:
    is_elf and any of them
    // is_elf and for any i in (0 .. elf.number_of_sections - 1): (
    //   elf.sections[i].name == ".rodata" and
    //     $1 in (elf.sections[i].offset .. elf.sections[i + 1].offset) and
    //     $2 in (elf.sections[i].offset .. elf.sections[i + 1].offset) and
    //     $3 in (elf.sections[i].offset .. elf.sections[i + 1].offset)
    // )
}
