# What is this
This tool is a combination of Yara and ClamAV to do malware scanning on Linux system. It was made as the idea that rkhunter and chkrootkit needs better replacement since both tools check absolute paths exist only.

# Why is this
This tool tries to solve problems of major tools
- chkrootkit and rkhunter do simple checks like absolute path on the system (rkhunter also has kernel symbols check. From my test, rkhunter couldn't detect Diamorphine in a infected system unless Diamorphine stop hidding itself). Absolute paths check is not so bad, considering the rootkit will hide all malicious files from walk directory method. However, it can't do anything if the attacker changed file paths.
- ClamAV has very huge RAM use everytime user runs a scan task (> 1Gb RAM). Too many old signatures are hashes -> missing modified malicious files. The binary's metadata engine lacks of proper metadata for ELF scan and there's no proper process scan on Linux. However, the engine has basic unpackers and it can handle archive files, document files, ...
- Yara is very well known engine with easy to write rules. It has very strong binary's metadata reader. However, it has no archive file handlers nor unpackers.
=> This tool try to solve the problem by using ClamAV to access files, and then use Yara as ClamAV's post scan to do signature matching. The quality of Yara's rule set is the scope to replace chkrootkit and rkhunter

# What about rules, signatures?
The rule is a collection of open source Yara rules that scan Linux's malwares and my custom research. The rule set is not perfect.

# What if this tool detects a file as a malware
This tool uses some custom Yara rules to detect malwares. However, there are some files has the same signatures. For example: Metasploit Framework's payload is an ELF file that has no sections. But there are some debug files and kernel modules are ELF files that has no sections at all. It's the same for high entropy rule.

# Why this tool doesn't detect this malware?
This project is a 1-man-project. I don't have power and resource to keep updating signatures all over the world like big AV companies. The tool uses ClamAV's engine and Yara's engine so it shares limitations of both engines. There's no real-time protection, behavior analysis, advanced heuristic analysis, advanced unpackers nor custom emulator. It's just a static file scan engine and I'm trying my best to provide signatures to scan malicious files

# How to build
The program requires Yara 4.2.3, ClamAV 0.103.7 and Nim 1.6.2. This program was developed and tested on Parrot OS 5.1. I haven't tested the newer versions of either Yara, Nim nor ClamAV. Other Linux distros weren't tested and the result is unknown.
To build this project, developer must install some libraries:
`sudo apt install libyara-dev libclamav-dev nim`
Then run
`make build`
Binary and signatures are at `build/`

To run this tool, user must install runtime library:
`sudo apt install libyara9 libclamav9`
To install inside system, run
`sudo make install`
To uninstall it, run
`sudo make uninstall`

# How to use
## To scan files or dirs
The scanner uses ClamAV engine to handle file access including decompression, file parsing, etc... Command to use:
To scan files, run command:
- `./rkscanmal --list-files /path/file1 /path/file2`
To scan directories, run command:
- `./rkscanmal --list-dirs /path/dir/1 /path/dir/2`

## To scan processes
ClamAv has no process scanner. This process scanner is a custom scanner using Yara engine. This custom engine uses the method PID Buster (called by Sandfly security) which does brute force all possibld PID number to scan hidden ProcFS.
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

## Detect hidden process
`--check-hidden-proc` will check if process is hidden from listing ProcFS data. It will slow down the process scanner.

# How about Rootkit detection?
Current engine has some Rootkit signatures. However I need to do more researches and tests to make sure it's able to detect Rootkits in the infected system. Detecting hidden files / directories wasn't tested

# Extra tools
- rkcompiler is a file to compile all custom Yara rules. No need to run this.
- rkhiddenproc: A quick tool that check if system is having hidden process. It's faster than rkscanmal's process scanner because it has no memory scanning
- rkscanrootkit: In development. The scope is to scan LD_PRELOAD and Loaded Kernel Module rootkits in the infected system.

# License, copyright
- Reused Yara engine under BSD-3-Clause.
- Reused ClamAV engine under GPL-2.0
- Original version of "unhide_procs" is under MIT license from Sandfly security. Reused researches from Sandfly security about Linux's malware and rootkit
- Reused some Yara rules from Tenable under BSD-3-Clause
- Some rules are having no custom licenses from Lacework Labs, Trend Micro
- Special thank to Nim lang community, ClamAV community, malware researcher Itay Cohen and everbody helped me this project
