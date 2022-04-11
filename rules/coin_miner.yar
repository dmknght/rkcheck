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

rule Coin_Miner_5
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = { 4D 65 6D 6F 72 79 3A 20 25 75 20 4B 69 42 2C 20 49 74 65 72 61 74 69 6F 6E 73 3A 20 25 75 2C 20 50 61 72 61 6C 6C 65 6C 69 73 6D 3A 20 25 75 20 6C 61 6E 65 73 2C 20 54 61 67 20 6C 65 6E 67 74 68 3A 20 25 75 20 62 79 74 65 73 } // "Memory: %u KiB, Iterations: %u, Parallelism: %u lanes, Tag length: %u bytes"
    $2 = { 42 6C 6F 63 6B 20 25 2E 34 75 20 5B 25 33 75 5D 3A 20 25 30 31 36 6C 78 } // "Block %.4u [%3u]: %016lx"
  condition:
    all of them
}


rule Connecticoin_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = { 63 6F 6E 6E 65 63 74 69 63 6F 69 6E 2E 6F 72 67 } // "connecticoin.org"
    $2 = { 22 43 6F 6E 6E 65 63 74 69 63 6F 69 6E 2D 51 74 22 } // "Connecticoin-Qt"
  condition:
    any of them
}

rule XMRStak_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
  strings:
    $1 = { 58 4D 52 53 54 41 4B 5F 56 45 52 53 49 4F 4E } // "XMRSTAK_VERSION"
    $2 = { 70 6F 6F 6C 2E 75 73 78 6D 72 70 6F 6F 6C 2E 63 6F 6D } // "pool.usxmrpool.com"
    $3 = { 64 6F 6E 61 74 65 2E 78 6D 72 2D 73 74 61 6B 2E 6E 65 74 } // "donate.xmr-stak.net"
    $4 = { 78 6D 72 2D 73 74 61 6B 2D 72 78 20 31 2E 30 2E 34 2D 72 78 20 36 35 61 64 65 37 34 } // "xmr-stak-rx 1.0.4-rx 65ade74"
  condition:
    any of them
}

rule Xmrig_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    // $1 = "donate.v2.xmrig.com"
    $1 = { 78 6D 72 69 67 2E 63 6F 6D } // "xmrig.com"
    $2 = { 63 72 79 70 74 6F 6E 69 67 68 74 2F 30 } // "cryptonight/0"
    $3 = { 63 72 79 70 74 6F 6E 69 67 68 74 2D 6D 6F 6E 65 72 6F 76 37 } // "cryptonight-monerov7"
    $4 = { 5F 5A 4E 35 78 6D 72 69 67 } // "_ZN5xmrig"
    // $5 = "miner.fee.xmrig.com"
    // $6 = "emergency.fee.xmrig.com"
    $7 = { 55 73 61 67 65 3A 20 78 6D 72 69 67 20 5B 4F 50 54 49 4F 4E 53 5D } // "Usage: xmrig [OPTIONS]"
    $8 = { 78 6D 72 69 67 2E 6A 73 6F 6E } // "xmrig.json"
    $9 = { 78 6D 72 69 67 4D 69 6E 65 72 } // "xmrigMiner" // fixme can't detect 0a79399*
  condition:
    any of them
}

rule NBMiner_682e {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "682e9645f289292b12561c3da62a059b"
    reference = "https://www.virustotal.com/gui/file/a819b4a95f386ae3bd8f0edc64e8e10fae0c21c9ae713b73dfc64033e5a845a1?nocache=1"
  strings:
    $1 = "/mnt/d/code/NBMiner"
    $2 = "_ZN5Miner10signalStopEv"
  condition:
    all of them
}