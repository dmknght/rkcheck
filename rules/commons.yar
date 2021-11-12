import "elf"


private rule is_elf {
  condition:
    uint32(0) == 0x464c457f
}

private rule elf_no_sections {
  condition:
    is_elf and elf.number_of_sections == 0
}


// rule generic_remove_syslogs {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     description = "Bash command to remove everything in /var/log/"
//     date = "12/11/1996"
//     refrence = "https://otx.alienvault.com/indicator/file/6138054a7de11c23b5c26755d7548c4096fa547cbb964ac78ef0fbe59d16c2da"
//   strings:
//     $ = "rm -rf /var/log/*"
//   condition:
//     all of them
// }

rule downloader_generic_wget {
  meta:
    description = "Bash commands to download and execute binaries using wget"
    reference = "https://www.trendmicro.com/en_us/research/19/d/bashlite-iot-malware-updated-with-mining-and-backdoor-commands-targets-wemo-devices.html"
    author = "Nong Hoang Tu"
    date = "12/11/2021"
    target = "File, process's cmd, memory"
  strings:
    $re1 = /wget([ \S])+[; ]+chmod([ \S])+\+x([ \S])+[; ]+.\/(\S)+/
  condition:
    all of them
}

rule downloader_generic_curl {
  meta:
    description = "Bash commands to download and execute binaries using CURL"
    refrence = "https://otx.alienvault.com/indicator/file/2557ee8217d6bc7a69956e563e0ed926e11eb9f78e6c0816f6c4bf435cab2c81"
    author = "Nong Hoang Tu"
    date = "12/11/2021"
    target = "File, process's cmd, memory"
  strings:
    $re1 = /curl([ \S])+\-O([ \S])+[; ]+cat([ >\.\S])+[; ]+chmod([ \S])+\+x([ \S\*])+[; ]+.\/([\S ])+/
  condition:
    all of them
}
