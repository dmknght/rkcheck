

private rule is_elf {
  condition:
    uint32(0) == 0x464c457f
}


private rule is_shebang {
  condition:
    uint32(0) == 0x752F2123 // "#!/u"
}

rule is_python {
  condition:
    is_shebang and (
      uint32(0xB) == 0x68747970 /* "htyp". Detect "#!/usr/bin/python" */ or
      uint32(0xF) == 0x68747970 // Detect "#!/usr/bin/env python"
    )
}
