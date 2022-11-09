import "elf"
import "hash"
include "rules/magics.yar"


rule Miner_GenA
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "Memory: %u KiB, Iterations: %u, Parallelism: %u lanes, Tag length: %u bytes" fullword ascii
    $2 = "Block %.4u [%3u]: %016lx" fullword ascii
  condition:
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}


rule Miner_GenB {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Stratum protocols used in coinminer. Usually in rodata"
  strings:
    $1 = "stratum+ssl://" ascii
    $2 = "stratum+tcp://" ascii
    $3 = "daemon+https://" ascii
    $4 = "daemon+http://" ascii
  condition:
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}


rule Miner_GenC {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Generic strings for coin miner"
  strings:
    $ = "Started Mining" fullword ascii
    $ = "Miner will restart" fullword ascii
    $ = "Miner not responding" fullword ascii
  condition:
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}


rule Connecticoin_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
  strings:
    $1 = "connecticoin.org" fullword ascii nocase
    $2 = "Connecticoin-Qt" fullword ascii
  condition:
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}


rule XMRStak_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "13/11/2021"
  strings:
    $1 = "XMRSTAK_VERSION" fullword ascii
    $2 = "pool.usxmrpool.com" fullword ascii nocase
    $3 = "donate.xmr-stak.net" fullword ascii nocase
    $4 = "xmr-stak-rx" fullword ascii
  condition:
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}


rule Xmrig_Generic
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
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
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
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
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}

rule GoMiner_b238 {
  meta:
    author = "Nong Hoang Tu"
    description = "A heavily striped Golang coin miner"
    md5 = "b238fe09791e169600fd3dbcdd0018a3"
  strings:
    $ = "Zpw9qKOmhDOzF3GWwJTB"
  condition:
    is_elf_file and
    (
      for any i in (0 .. elf.number_of_sections):
      (
        any of them in (elf.sections[i].offset .. elf.sections[i].offset + elf.sections[i].size)
      ) or
      for any i in (0 .. elf.number_of_segments):
      (
        any of them in (elf.segments[i].virtual_address .. elf.segments[i].virtual_address + elf.segments[i].memory_size)
      )
    )
}
