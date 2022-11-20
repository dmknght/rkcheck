import "magics"


rule BrokePkg_Generic {
  strings:
    $ = "[brokepkg]"
  condition:
    sys_kernel_magic and all of them
}


rule Diamorphine_Generic {
  strings:
    $ = "[diamorphine]" fullword ascii
  condition:
    sys_kernel_magic and all of them
}


rule SusModules_Generic {
  strings:
    $ = "hook kill" fullword ascii
    $ = "pid_hide" fullword ascii
    $ = "module_hide" fullword ascii
    $ = "port_hide" fullword ascii
    $ = "give_root" fullword ascii
  condition:
    sys_kernel_magic and 3 of them
}
