import "elf"

/*
  https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
  Rules to detect ELF file.
  vmem_start is a external variable that is provided by
  custom compiler and scanner. It should be 0 or start of
  process's memory block mapped in procfs.
  elf_type has offset 0x10, size 2
*/

private rule elf_magic {
  condition:
    uint32(vmem_start) == 0x464c457f
}

private rule elf_exec {
  strings:
    $magic = "\x7fELF"
  condition:
    (elf_magic and uint8(vmem_start + 0x10) == elf.ET_EXEC) or
    ($magic and uint8(@magic[1] + 0x10) == elf.ET_EXEC)
}

private rule elf_dyn {
  strings:
    $magic = "\x7fELF"
  condition:
    (elf_magic and uint8(vmem_start + 0x10) == elf.ET_DYN) or
    ($magic and uint8(@magic[1] + 0x10) == elf.ET_DYN)
}

private rule elf_rel {
  strings:
    $magic = "\x7fELF"
  condition:
    (elf_magic and uint8(vmem_start + 0x10) == elf.ET_REL) or
    ($magic and uint8(@magic[1] + 0x10) == elf.ET_REL)
}

private rule xdg_desktop_entry {
  condition:
    uint32(0) == 0x7365445B and uint32(11) == 0x5D797274
}


private rule is_xml {
  condition:
    uint32(0) == 0x6d783f3c
}

/*
  Scan system kernel modules
*/

private rule sys_kernel_magic {
  condition:
    uint16(0) == 0x5f5f
}

// private rule is_shebang {
//   condition:
//     uint32(0) == 0x752F2123 // "#!/u". Meant to detect "#!/usr/bin/"
// }


// private rule is_python {
//   condition:
//     is_shebang and (
//       uint32(0xB) == 0x68747970 /* "htyp". Detect "#!/usr/bin/python" */ or
//       uint32(0xF) == 0x68747970 /* Detect "#!/usr/bin/env python" */ or
//       uint32(0x11) == 0x68747970 /* Detect #!/usr/local/bin/python */
//     )
// }


// private rule is_ruby {
//   condition:
//     is_shebang and (
//       uint32(0xB) == 0x79627572 /* "ruby". Detect "#!/usr/bin/ruby" */ or
//       uint32(0xF) == 0x79627572 /* "#!/usr/bin/env ruby" */ or
//       uint32(0x11) == 0x79627572 /* #!/usr/local/bin/ruby */
//     )
// }
// TODO add shebang for perl, php, bash and other scripting languages