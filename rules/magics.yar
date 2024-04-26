/*
  https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
  Rules to detect ELF file.
*/

private rule elf_magic {
  condition:
    uint32(0) == 0x464c457f
}

private rule elf_rel {
  condition:
    elf_magic and uint16(16) == 0x01
}

private rule elf_exec {
  condition:
    elf_magic and uint16(16) == 0x02
}

private rule elf_dyn {
  condition:
    elf_magic and uint16(16) == 0x03
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
