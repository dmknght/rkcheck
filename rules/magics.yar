/*
  https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
  Rules to detect ELF file.
*/

private rule elf_magic {
  strings:
    $magic = {7f 45 4c 46 [6] (00 | 01 | 02 | 03 | 04 )}
  condition:
    // $magic and not defined uint8(@magic[0] - 1)
    $magic at 0
}

private rule elf_rel {
  strings:
    $magic = {7f 45 4c 46 [6] 01}
  condition:
    // $magic and not defined uint8(@magic[0] - 1)
    $magic at 0
}

private rule elf_exec {
  strings:
    $magic = {7f 45 4c 46 [6] 02}
  condition:
    // $magic and not defined uint8(@magic[0] - 1)
    $magic at 0
}

private rule elf_dyn {
  strings:
    $magic = {7f 45 4c 46 [6] 03}
  condition:
    // $magic and not defined uint8(@magic[0] - 1)
    $magic at 0
}


private rule xdg_desktop_entry {
  condition:
    uint32(0) == 0x7365445B and uint32(11) == 0x5D797274
}


private rule xml_magic {
  condition:
    uint32(0) == 0x6d783f3c
}

// TODO add shebang for perl, php, bash and other scripting languages
private rule shebang_magic {
  condition:
    uint16(0) == 0x2123
}


private rule pyc_magic {
  // First 2 bytes: Py version https://github.com/google/pytype/blob/main/pytype/pyc/magic.py
  condition:
    uint16(2) == 0x0a0d
}
