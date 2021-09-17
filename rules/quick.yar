import "elf"
import "hash"


private rule is_elf {
  condition:
    uint32(0) == 0x464c457f
}

private rule elf_no_sections {
  condition:
    is_elf and elf.number_of_sections == 0
}

rule Suspicious_ELF_NoSection {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Suspicious ELF files. File has no section and file size < 1KB. Usually see by Metasploit's stageless payloads"
  condition:
    elf_no_sections and filesize < 1KB
}

rule Metasploit_Payload_Staged {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Scan Metasploit's Linux staged payload by checking section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "fbeb0b6fd7a7f78a880f68c413893f36"
    )
}

rule Linux_Mirai_1 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt and Tsunami variants (named by ClamAV) using section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "b748e0aa34cc3bb4dcf0f803be00e8ae"
    )
}

rule Linux_Mirai_2 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants (named by ClamAV) using section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "90d8eebc2a34162c49ec31cfc660cec1"
    )
}

rule Linux_Mirai_3 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detect some Mirai's variants including Gafgyt variants (named by ClamAV) using section hash"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "68dd3bd106aab3e99d9a65e4f9bfa7f1" or
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "a4b1a9d3f3622ccb54e615de8005f87f"
    )
}

rule bash_door {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/tmp/mcliZokhb" or file_path == "/tmp/mclzaKmfa"
}

rule slapper_installed {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/tmp/.bugtraq" or file_path == "/tmp/.bugtraq.c" or file_path == "/tmp/.cinik" or file_path == "/tmp/.b" or file_path == "/tmp/httpd" or file_path == "/tmp./update" or file_path == "/tmp/.unlock" or file_path == "/tmp/.font-unix/.cinik" or file_path == "/tmp/.cinik"
}

rule mithras_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/lib/locale/uboot"
}

rule omega_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/chr"
}

rule kenga3_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/include/. ."
}

rule sadmind_iis_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/cuc"
}

rule rsha {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/bin/kr4p" or file_path == "/usr/bin/n3tstat" or file_path == "/usr/bin/chsh2" or file_path == "/usr/bin/slice2" or file_path == "/etc/rc.d/rsha"
}

rule old_rootkits {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/include/rpc/ ../kit" or file_path == "/usr/include/rpc/ ../kit2" or file_path == "/usr/doc/.sl" or file_path == "/usr/doc/.sp" or file_path == "/usr/doc/.statnet" or file_path == "/usr/doc/.logdsys" or file_path == "/usr/doc/.dpct" or file_path == "/usr/doc/.gifnocfi" or file_path == "/usr/doc/.dnif" or file_path == "/usr/doc/.nigol"
}

rule telekit_trojan {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/hda06" or file_path == "/usr/info/libc1.so"
}

rule tc2_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/info/.tc2k" or file_path == "/usr/bin/util" or file_path == "/usr/sbin/initcheck" or file_path == "/usr/sbin/ldb"
}

rule shitc {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/bin/home" or file_path == "/sbin/home" or file_path == "/usr/sbin/in.slogind"
}

rule rh_sharpe {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/bin/.ps" or file_path == "/usr/bin/cleaner" or file_path == "/usr/bin/slice" or file_path == "/usr/bin/vadim" or file_path == "/usr/bin/.ps" or file_path == "/bin/.lpstree" or file_path == "/usr/bin/.lpstree" or file_path == "/usr/bin/lnetstat" or file_path == "/bin/lnetstat" or file_path == "/usr/bin/ldu" or file_path == "/bin/ldu" or file_path == "/usr/bin/lkillall" or file_path == "/bin/lkillall" or file_path == "/usr/include/rpcsvc/du"
}

rule showtee_romanian_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/include/addr.h" or file_path == "/usr/include/file.h" or file_path == "/usr/include/syslogs.h" or file_path == "/usr/include/proc.h"
}

rule lrk_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/ida/.inet"
}

rule zk_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/share/.zk" or file_path == "/usr/share/.zk/zk" or file_path == "/etc/1ssue.net" or file_path == "/usr/X11R6/.zk" or file_path == "/usr/X11R6/.zk/xfs" or file_path == "/usr/X11R6/.zk/echo" or file_path == "/etc/sysconfig/console/load.zk"
}

rule ramen_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/lib/ldlibps.so" or file_path == "/usr/lib/ldlibns.so" or file_path == "/usr/lib/ldliblogin.so" or file_path == "/usr/src/.poop" or file_path == "/tmp/ramen.tgz" or file_path == "/etc/xinetd.d/asp"
}

rule maniac_rk {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/bin/mailrc"
}

rule bmbl_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/etc/.bmbl" or file_path == "/etc/.bmbl/sk"
}

rule suckit_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/lib/.x" or file_path == "/lib/sk"
}

rule adore_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/etc/bin/ava" or file_path == "/etc/sbin/ava"
}

rule ldp_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/.kork" or file_path == "/bin/.login" or file_path == "/bin/.ps"
}

rule romanian_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/sbin/initdl" or file_path == "/usr/sbin/xntps"
}

rule illogic_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/lib/security/.config" or file_path == "/usr/bin/sia" or file_path == "/etc/ld.so.hash"
}

rule bobkit_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/include/.../" or file_path == "/usr/lib/.../" or file_path == "/usr/sbin/.../" or file_path == "/usr/bin/ntpsx" or file_path == "/tmp/.bkp" or file_path == "/usr/lib/.bkit-"
}

rule monkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/lib/defs"
}

rule override_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/grid-hide-pid-" or file_path == "/dev/grid-unhide-pid-" or file_path == "/dev/grid-show-pids" or file_path == "/dev/grid-hide-port-" or file_path == "/dev/grid-unhide-port-"
}

rule madalin_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/include/icekey.h" or file_path == "/usr/include/iceconf.h" or file_path == "/usr/include/iceseed.h"
}

rule solaris_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/var/adm/.profile" or file_path == "/var/spool/lp/.profile" or file_path == "/var/adm/sa/.adm" or file_path == "/var/spool/lp/admins/.lp"
}

rule phalanx_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/share/.home*" or file_path == "/usr/share/.home*/tty" or file_path == "/etc/host.ph1" or file_path == "/bin/host.ph1"
}

rule ark_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/ptyxx"
}

rule tribe_bot {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/wd4"
}

rule cback_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/tmp/cback" or file_path == "/tmp/derfiq"
}

rule optickit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/bin/xchk" or file_path == "/usr/bin/xsf" or file_path == "/usr/bin/xsf" or file_path == "/usr/bin/xchk"
}

rule anonoiyng_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/sbin/mech" or file_path == "/usr/sbin/kswapd"
}

rule loc_rookit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/tmp/xp" or file_path == "/tmp/kidd0.c" or file_path == "/tmp/kidd0"
}

rule showtee {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/lib/.egcs" or file_path == "/usr/lib/.wormie" or file_path == "/usr/lib/.kinetic" or file_path == "/usr/lib/liblog.o" or file_path == "/usr/include/cron.h" or file_path == "/usr/include/chk.h"
}

rule zarwt_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/bin/imin" or file_path == "/bin/imout"
}

rule lion_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/.lib" or file_path == "/dev/.lib/1iOn.sh" or file_path == "/bin/mjy" or file_path == "/bin/in.telnetd" or file_path == "/usr/info/torn"
}

rule suspicious_files {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/etc/rc.d/init.d/rc.modules" or file_path == "/lib/ldd.so" or file_path == "/usr/man/muie" or file_path == "/usr/X11R6/include/pain" or file_path == "/usr/bin/sourcemask" or file_path == "/usr/bin/ras2xm" or file_path == "/usr/bin/ddc" or file_path == "/usr/bin/jdc" or file_path == "/usr/sbin/in.telnet" or file_path == "/sbin/vobiscum" or file_path == "/usr/sbin/jcd" or file_path == "/usr/sbin/atd2" or file_path == "/usr/bin/ishit" or file_path == "/usr/bin/.etc" or file_path == "/usr/bin/xstat" or file_path == "/var/run/.tmp" or file_path == "/usr/man/man1/lib/.lib" or file_path == "/usr/man/man2/.man8" or file_path == "/var/run/.pid" or file_path == "/lib/.so" or file_path == "/lib/.fx" or file_path == "/lib/lblip.tk" or file_path == "/usr/lib/.fx" or file_path == "/var/local/.lpd" or file_path == "/dev/rd/cdb" or file_path == "/dev/.rd/" or file_path == "/usr/lib/pt07" or file_path == "/usr/bin/atm" or file_path == "/tmp/.cheese" or file_path == "/dev/.arctic" or file_path == "/dev/.xman" or file_path == "/dev/.golf" or file_path == "/dev/srd0" or file_path == "/dev/ptyzx" or file_path == "/dev/ptyzg" or file_path == "/dev/xdf1" or file_path == "/dev/ttyop" or file_path == "/dev/ttyof" or file_path == "/dev/hd7" or file_path == "/dev/hdx1" or file_path == "/dev/hdx2" or file_path == "/dev/xdf2" or file_path == "/dev/ptyp" or file_path == "/dev/ptyr" or file_path == "/sbin/pback" or file_path == "/usr/man/man3/psid" or file_path == "/proc/kset" or file_path == "/usr/bin/gib" or file_path == "/usr/bin/snick" or file_path == "/usr/bin/kfl" or file_path == "/tmp/.dump" or file_path == "/var/.x" or file_path == "/var/.x/psotnic"
}

rule apa_kit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/share/.aPa"
}

rule enye_sec_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/etc/.enyelkmHIDE^IT.ko"
}

rule rk17 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/bin/rtty" or file_path == "/bin/squit" or file_path == "/sbin/pback" or file_path == "/proc/kset" or file_path == "/usr/src/linux/modules/autod.o" or file_path == "/usr/src/linux/modules/soundx.o"
}

rule trk_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/bin/soucemask" or file_path == "/usr/bin/sourcemask"
}

rule scalper_installed {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/tmp/.uua" or file_path == "/tmp/.a"
}

rule hidr00tkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/var/lib/games/.k"
}

rule beastkit_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/local/bin/bin" or file_path == "/usr/man/.man10" or file_path == "/usr/sbin/arobia" or file_path == "/usr/lib/elm/arobia" or file_path == "/usr/local/bin/.../bktd"
}

rule shv5_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/lib/libsh.so" or file_path == "/usr/lib/libsh"
}

rule esrk_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/lib/tcl5.3"
}

rule shkit_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/lib/security/.config" or file_path == "/etc/ld.so.hash"
}

rule knark_installed {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/proc/knark" or file_path == "/dev/.pizda" or file_path == "/dev/.pula" or file_path == "/dev/.pula"
}

rule volc_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/lib/volc" or file_path == "/usr/bin/volc"
}

rule fu_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/sbin/xc" or file_path == "/usr/include/ivtype.h" or file_path == "/bin/.lib"
}

rule ajakit_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/lib/.ligh.gh" or file_path == "/lib/.libgh.gh" or file_path == "/lib/.libgh-gh" or file_path == "/dev/tux" or file_path == "/dev/tux/.proc" or file_path == "/dev/tux/.file"
}

rule monkit_found {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/usr/lib/libpikapp.a"
}

rule t0rn_rootkit {
  /*
    TODO add more signatures using analysis url and chkrootkit version
    THIS KIT WILL REPLACE SYSTEM FILES WITH TROJANIZED VERSION. NEED TO VERIFY THEM AS WELL
  */
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
    analysis_url = "https://www.f-secure.com/v-descs/torn.shtml"
  condition:
    file_path == "/usr/src/.puta" or file_path == "/usr/info/.t0rn" or file_path == "/lib/ldlib.tk" or file_path == "/etc/ttyhash" or file_path == "/sbin/xlogin"
}

rule adore_worm {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/.shit/red.tgz" or file_path == "/usr/lib/libt" or file_path == "/usr/bin/adore"
}

rule a_worm_55808 {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/tmp/.../a" or file_path == "/tmp/.../r"
}

rule tuxkit_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/dev/tux" or file_path == "/usr/bin/xsf" or file_path == "/usr/bin/xchk"
}

rule reptile_rootkit {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Automation Yara rule generated from ossec-rootkit.conf"
    url = "https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf"
  condition:
    file_path == "/reptile/reptile_cmd" or file_path == "/lib/udev/reptile"
}

rule Coin_miner_1
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Detected Multios.Coinminer.Miner-6781728-2 (ClamAV)"
    /*
      There are some interesting strings in section .rodata Maybe write it as other signatures?
        $1 = "/dev/null"
        $2 = "/proc/self/exe"
        $3 = "/bin/sh"
        $4 = "/dev/urandom"
    */
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "d2c0aaec378884e0d4eef2d3bb1db8fc"
    )
}


rule Trojan_golang_1
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux Trojan written in Golang. https://www.virustotal.com/gui/file/751014e0154d219dea8c2e999714c32fd98f817782588cd7af355d2488eb1c80"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "dfd54f22d3a3bb072d34c424aa554500"
    )
}


rule Coin_miner_2
{
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    description = "Linux coin miner https://www.virustotal.com/gui/file/0b1c49ec2d53c4af21a51a34d9aa91e76195ceb442480468685418ba8ece1ba6"
  condition:
    is_elf and
    for any i in (0 .. elf.number_of_sections - 1): (
      hash.md5(elf.sections[i].offset, elf.sections[i].size) == "639b1b0a43f34ed06028d6fd9214135a"
    )
}
