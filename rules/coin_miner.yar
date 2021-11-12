import "elf"
import "hash"
include "rules/commons.yar"


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
