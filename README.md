# What is this
This tool is a combination of Yara and ClamAV to do malware scanning on Linux system. It was made as the idea that rkhunter and chkrootkit need better replacement since both tools check absolute paths exist only.

# Feature comparison
Comparison of ClamAV and Yara

| | ClamAV | Yara |
|---|---|---|
| File scan | &#9745; | &#9745; |
| Memory scan | &#9744; | &#9745; |
| File parser | &#9745; | &#9744; |
| Decompresser | &#9745; | &#9744; |
| Unpacker | Some basic unpackers | &#9744; |
| Strong metadata matching | Only PE file | &#9745; |
| Custom signatures | &#9745; | &#9745; |
| Strong signature syntax | &#9744; | &#9745; |
| Lightweight runtime | &#9744; | &#9745; |
| Real-time protection | &#9744; | &#9744;|
| Emulator | &#9744; | &#9744; |

-> rkcheck combines advantages of 2 engines with Nim lang to provide a strong, easy to maintain and modify open-source malware scanner.

Comparison of ckrootkit and rkhunter (scan module only)

| | rkhunter | chkrootkit |
|---|---|---|
| File / dir scan method | File / dir exists | File / dir exists |
| Kernel symbol scan | Read `/proc/kallsyms` | &#9744; |
| Metadata scan | &#9744; | &#9744; |

There are multiple ways to bypass these scanners:
1. Change absolute path of binaries
2. Hook sys call (LKM / eBPF) or libc functions (LD_PRELOAD) to hijack data

Diamorphine rootkit hides its kernel symbols inside `/proc/kallsyms`. Therefore, the kernel symbols exposed in `/proc/kallsyms`. Rkhunter couldn't detect the rootkit until Diamorphine **unhide** itself.
Here's my [new method](https://sourceforge.net/p/rkhunter/feature-requests/52/) to detect Diamorphine rootkit requested on rkhunter project.

Since LD_PRELOAD rootkit hooks libc functions, a static binary can defeat this rootkit type easily. However, kernel land rootkit is a harder story. Research a proper way to defeat all rootkit types is a goal of this project

# What about rules and signatures?
The rule is a collection of open source Yara rules that scan Linux's malwares and my custom research. The rule set is not perfect.

# What if this tool detects a file as a malware
This tool uses some custom Yara rules to detect malwares. However, there are some files has the same signatures. For example: Metasploit Framework's payload is an ELF file that has no sections. But there are some debug files and kernel modules are ELF files that has no sections at all. It's the same for high entropy rule, check file imports, ...

# Why this tool doesn't detect this malware?
This project is a 1-man-project. I don't have power and resource to keep updating signatures all over the world like big AV companies. The tool uses ClamAV's engine and Yara's engine so it shares limitations of both engines. There's no real-time protection, behavior analysis, advanced heuristic analysis, advanced unpackers nor custom emulator. It's just a static file scan engine and I'm trying my best to provide signatures to scan malicious files

# How to build

Tested platform:
- Parrot 5.1.2
- Yara 4.2.3
- ClamAV 0.103.7
- Nim 1.6.2

To build this project, developer must install some libraries:
- `sudo apt install libyara-dev libclamav-dev nim`
NOTE: on Parrot OS 5.1, Yara must be installed from backports:
- `sudo apt install libyara-dev libclamav-dev nim -t parrot-backports`

Then run
- `make build`

To install inside system, run
- `sudo make install`
To uninstall it, run
- `sudo make uninstall`
Binary and signatures are in dir `build/`

To run this tool, user must install runtime library:
- `sudo apt install libyara9 libclamav9`

# How to use
## To scan files or dirs
The scanner uses ClamAV engine to handle file access including decompression, file parsing, etc... Command to use:

To scan files, run command:
- `./rkscanmal --list-files /path/file1 /path/file2`

To scan directories, run command:
- `./rkscanmal --list-dirs /path/dir/1 /path/dir/2`

## To scan processes
ClamAv has no process scanner. This process scanner is a custom scanner using Yara engine. This custom engine uses the method PID Buster (called by Sandfly Security) which does brute force all possible PID number to scan hidden ProcFS.

To scan list of processes, run command:
- `./rkscanmal --list-procs pid1,pid2,pid3`. Pid is process id and must be a number.

To scan all running processes inside system, run command:
- `./rkscanmal --all-procs`

If `--all-procs` is provided, the scanner will ignore list-procs

# Advanced scan options
## Use custom database
User can use custom Yara rules (either compiled or text file) by adding `--path-yaradb /path/to/yara/signature`:
- `./rkscanmal --path-yaradb /tmp/rule.yara --list-dirs /var/`

User can use both Yara's rules and ClamAV's signatures by adding `--use-clamdb`. This option will take signatures from `/var/lib/clamav/` by default
- `./rkscanmal --list-dirs /home/ --use-clamdb`

If user want to use custom ClamAV's signatures, user can use `--path-clamdb`. This option will enable using ClamAV's signature without adding `--use-clamdb`
- `./rkscanmal --path-clamdb /home/user/Download/clamav-signatures/ --list-dirs /root/`

Process scanner doesn't use ClamAV engine so using custom ClamAV engine will not change the scan result.

## Enable ClamAV Debug mode (file scan only)
To enable LibClamAV debug mode, user can add `--clam-debug`

# How about Rootkit detection?
Current engine has some Rootkit signatures. However I need to do more researches and tests to make sure it's able to detect Rootkits in the infected system. Detecting hidden files / directories weren't tested

# Extra tools
- rkcompiler is a file to compile all custom Yara rules. This won't be installed into system using `make install`
- rkhiddenproc: A quick tool that check if system is having hidden process. It's faster than rkscanmal's process scanner because it has no memory scanning
- rkscanpreload: ~~A simple scanner, similar to `rkscanmal` which is staticly compiled. This tool has no ClamAV as the file handler. The point of making it was to scan system was infected by LD_PRELOAD rootkit, therefore dynamically linked ELF can't read data hooked by this Rootkit family. The current ClamAV version on Debian has no static lib to do static compile so I have to write this standalone tool. This tool also do parsing `/etc/ld.so.preload` to check libraries in there. (Note: it doesn't support checking ENV right now)~~. Commented in Makefile. Researching for better solutions that can work on both user-land rootkits and kernel-land rootkits

# Roadmaps
- Update the tool with latest ClamAV and Yara engine. Support static build
- Research eBPF so this project can have proper way to detect kernel-land and user-land rootkits

# License, copyright
- Reused Yara engine under BSD-3-Clause.
- Reused ClamAV engine under GPL-2.0
- Original version of "unhide_procs" is under MIT license from Sandfly security. Reused researches from Sandfly security about Linux's malware and rootkit
- Reused some Yara rules from Tenable under BSD-3-Clause
- Some rules are having no custom licenses from Lacework Labs, Trend Micro
- Special thank to Nim lang community, ClamAV community, malware researcher Itay Cohen and everbody helped me this project
