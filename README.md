# What is this
This tool is a combination of Yara and ClamAV to do malware scanning on Linux system. It was made as the idea that rkhunter and chkrootkit needs better replacement since both tools check absolute paths exist only.

# Why is this
This tool tries to solve problems of major (or famous) tools
| Tool | Scan method | Problem |
|---|---|---|
| chkrootkit | Check if absolute paths exist (dirs and files) | - Rootkit hooks stat, lstat could compromise the results |
| rkhunter | - Check if absolute paths exist (dirs and files) <br> - Support checking kernel symbols at /proc/ kallsyms | - Rootkit hooks stat lstat could compromise the results <br> - Rootkit hooks program reading kallsysms, compromise the scan results |
| Yara | Powerful signature based and metadata parsing | - No file decompression <br> - No real-time scan <br> - No unpackers |
| ClamAV | Signature based, support file decompression, document parsers, some basic unpackers, ... | - No process scan on Linux (last time i checked) <br> - Ram usage is very huge (more than 1gb ram after load all DB last time i checked) <br> - Mainly based on string matching and hashing. Lack of metadata parser for ELF file and March-O file. Poor metadata parsing for PE file compare to Yara <br> - Rules are not so user-friendly: custom format with hex encoded strings


p/s: chkrootkit and rkhunter has some more custom functions. This table focused on the malware checking only.

p/s2: all of them don't have advanced technologies compare to modern Antivirus: emulators, behavior analyzer, ....

=> This tool try to solve the problem by using ClamAV's engine to handle files, and then use Yara as ClamAV's post scan to do signature matching. To replace chkrootkit and rkhunter, my scope is to learn eBPF scripting to write real-time scanner to detect kernel's hooking and more (similar to tracee).

# What about rules, signatures?
The rule is a collection of open source Yara rules that scan Linux's malwares and my custom research. The rule set is not perfect.

# What if this tool detects a file as a malware
This tool uses some custom Yara rules to detect malwares. However, there are some files has the same signatures. For example: Metasploit Framework's payload is an ELF file that has no sections. But there are some debug files and kernel modules are ELF files that has no sections at all. It's the same for high entropy rule, check file imports, ...

# Why this tool doesn't detect this malware?
This project is a 1-man-project. I don't have power and resource to keep updating signatures all over the world like big AV companies. The tool uses ClamAV's engine and Yara's engine so it shares limitations of both engines. There's no real-time protection, behavior analysis, advanced heuristic analysis, advanced unpackers nor custom emulator. It's just a static file scan engine and I'm trying my best to provide signatures to scan malicious files

# How to build
The program requires Yara 4.2.3, ClamAV 0.103.7 and Nim 1.6.2. This program was developed and tested on Parrot OS 5.1. I haven't tested the newer versions of either Yara, Nim nor ClamAV. Other Linux distros weren't tested and the result is unknown.

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
ClamAv has no process scanner. This process scanner is a custom scanner using Yara engine. This custom engine uses the method PID Buster (called by Sandfly Security) which does brute force all possibld PID number to scan hidden ProcFS.

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
Current engine has some Rootkit signatures. However I need to do more researches and tests to make sure it's able to detect Rootkits in the infected system. Detecting hidden files / directories wasn't tested

# Extra tools
- rkcompiler is a file to compile all custom Yara rules. This won't be installed into system using `make install`
- rkhiddenproc: A quick tool that check if system is having hidden process. It's faster than rkscanmal's process scanner because it has no memory scanning
- rkscanpreload: A simple scanner, similar to `rkscanmal` which is staticly compiled. This tool has no ClamAV as the file handler. The point of making it was to scan system was infected by LD_PRELOAD rootkit, therefore dynamically linked ELF can't read data hooked by this Rootkit family. The current ClamAV version on Debian has no static lib to do static compile so I have to write this standalone tool. This tool also do parsing `/etc/ld.so.preload` to check libraries in there. (Note: it doesn't support checking ENV right now)

# Roadmaps
- Update the tool with latest ClamAV and Yara engine
- Try static build for `rkscanmal` so no need to have `rkscanpreload`.
- Research eBPF so this project can have proper way to detect Rootkit (LKM and eBPF rootkits)

# License, copyright
- Reused Yara engine under BSD-3-Clause.
- Reused ClamAV engine under GPL-2.0
- Original version of "unhide_procs" is under MIT license from Sandfly security. Reused researches from Sandfly security about Linux's malware and rootkit
- Reused some Yara rules from Tenable under BSD-3-Clause
- Some rules are having no custom licenses from Lacework Labs, Trend Micro
- Special thank to Nim lang community, ClamAV community, malware researcher Itay Cohen and everbody helped me this project
