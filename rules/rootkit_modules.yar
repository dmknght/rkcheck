
rule Diamorphine_Generic {
  strings:
    $ = "module_hide [diamorphine]" fullword ascii
    $ = "hacked_kill [diamorphine]" fullword ascii
    $ = "give_root [diamorphine]" fullword ascii
  condition:
    sys_kernel_magic and all of them
}
