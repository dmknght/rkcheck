private rule sys_kernel_start {
  condition:
    uint16(0) == 0x5f5f
}


rule KernModul_Diamorphine {
  strings:
    $ = "module_hide [diamorphine]" fullword ascii
    $ = "hacked_kill [diamorphine]" fullword ascii
    $ = "give_root [diamorphine]" fullword ascii
  condition:
    sys_kernel_start and all of them
}
