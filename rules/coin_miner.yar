import "elf"
import "hash"
include "rules/magics.yar"


rule Miner_Generic_A
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "Memory: %u KiB, Iterations: %u, Parallelism: %u lanes, Tag length: %u bytes" ascii
    $2 = "Block %.4u [%3u]: %016lx" ascii
  condition:
    all of them
}


rule Miner_Generic_B {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Stratum protocols used in coinminer. Usually in rodata"
  strings:
    $1 = "stratum+ssl://" ascii nocase
    $2 = "stratum+tcp://" ascii nocase
  condition:
    any of them
}


rule Connecticoin_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "connecticoin.org" ascii nocase
    $2 = "Connecticoin-Qt" ascii
  condition:
    any of them
}


rule XMRStak_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
  strings:
    $1 = "XMRSTAK_VERSION" ascii
    $2 = "pool.usxmrpool.com" ascii nocase
    $3 = "donate.xmr-stak.net" ascii nocase
    $4 = "xmr-stak-rx" ascii
  condition:
    any of them
}


rule Xmrig_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "xmrig.com" ascii nocase
    $2 = "cryptonight/0" ascii
    $3 = "cryptonight-monerov7" ascii
    $4 = "_ZN5xmrig" ascii
    // $5 = "miner.fee.xmrig.com"
    // $6 = "emergency.fee.xmrig.com"
    $7 = "Usage: xmrig [OPTIONS]" ascii
    $8 = "xmrig.json" ascii
    $9 = "xmrigMiner" ascii
    $10 = "donate.v2.xmrig.com" ascii nocase
    $11 = "api.xmrig.com" ascii nocase
  condition:
    any of them
}


rule XMRig_ee0e
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "XMRig golang coin miner, section hash ea5f61d48cc64bcba47ed3d75ccc3e59"
    hash = "ee0e8516bfc431cb103f16117b9426c79263e279dc46bece5d4b96ddac9a5e90"
    hash = "4c38654e08bd8d4c2211c5f0be417a77759bf945b0de45eb3581a2beb9226a29" // Can't find string base detection
  strings:
    $1 = "Zpw9qKOmhDOzF3GWwJTB/n0Y7l4tNbKi_20SnKY2V/abOQbe22wGJEqbNFCaQA/-otqwZsVDBRU3_zW503b" ascii
    $2 = "xmrigvertar" ascii
    $3 = "jcxmrig" ascii
  condition:
    $1 at 0xfac or all of them
}


rule NBMiner_682e {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "682e9645f289292b12561c3da62a059b"
    reference = "https://www.virustotal.com/gui/file/a819b4a95f386ae3bd8f0edc64e8e10fae0c21c9ae713b73dfc64033e5a845a1?nocache=1"
  strings:
    $1 = "/mnt/d/code/NBMiner" ascii
    $2 = "_ZN5Miner10signalStopEv" ascii
  condition:
    all of them
}

rule GMiner_dbc5 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    hash = "dbc5d43763ea01043430f6cf325171d8"
  strings:
    $ = "GMiner" ascii
    $ = "Started Mining on GPU" ascii
    $ = "Miner will restart" ascii
    $ = "Miner not responding" ascii
    $ = "EthereumStratum" ascii
  condition:
    3 of them
}
