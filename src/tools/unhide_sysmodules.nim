import os
import strutils


const
  f_sys_modules = "/proc/modules"
  d_sys_modules = "/sys/module/"

#[
  f_sys_modules -> /proc/modules is all loaded kernel modules. If a module is hidden, it will not be there.
  d_sys_modules -> /sys/modules/ is a sysfs-modules that won't be hidden (tested with Diamorphine rootkit version May 12th 2021)
]#


proc get_sys_modules_procfs(list_modules: var seq[string]) =
  for line in lines(f_sys_modules):
    list_modules.add(line.split()[0])


proc find_hidden_kernel_modules() =
  var
    kernel_modules: seq[string]

  kernel_modules.get_sys_modules_procfs()
  for kind, path in walkDir(d_sys_modules):
    if kind == pcDir:
      let current_module_name = splitPath(path).tail
      if current_module_name notin kernel_modules:
        echo "Found a hidden kernel module ", current_module_name

find_hidden_kernel_modules()
