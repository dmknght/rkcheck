# What is this
This tool is a combination of Yara and ClamAV to do malware scanning on Linux system. It was made as the idea that rkhunter and chkrootkit need better replacement since both tools check absolute paths exist only.

# Feature comparison
Comparison of ClamAV and Yara (CPU and Memory consuption is updated bellow the table)

| | ClamAV | Yara |
|---|---|---|
| File scan | &#9745; | &#9745; |
| File parser | Doc, PDF and various file parsers | PE, ELF, ... as modules. However, the file parsers of Yara are much stronger than ClamAV |
| Memory scan | N/A on Linux by default | &#9745; |
| Decompresser | &#9745; | &#9744; |
| Unpacker | Some basic unpackers | &#9744; |
| Strong metadata matching | Only PE file | &#9745; |
| Custom signatures | &#9745; | &#9745; |
| Strong signature syntax | &#9744; | &#9745; |
| Real-time protection | &#9744; | &#9744;|
| Emulator | &#9744; | &#9744; |

-> rkcheck combines advantages of 2 engines with Nim lang to provide a strong, easy to maintain and modify open-source malware scanner. The memory scan with ClamAV is being developed, support different signature writing methods.

# Peformance comparison
The result bellow was tested against 215 sample. The ruleset was string matching rules. Some important information before the test result

ClamAV has 2 signature types:
- Traditional: logical signatures / hash-based signatures, ... in text file
- Bytecode: Use LLVM to execute bytecodes. The compiled rule has the logical signature (similar to traditional one) **and** the bytecodes (encoded char)

Different signature types could have different time consumption and memory consumption affects by database loading method and signature execution method. In theory, bytecode signature will costs less memory when the database is huge.

Meanwhile, Yara signatures have two different rule types:
- Text-based rules: The engine will load it into memory and compile.
- Compiled rules: Pre-compiled rules.

Both rule types are compiled to bytecodes. The load time might be different (small value). Yara engine loads everything in the rules into memory. The memory consumption will be huge if the ruleset is huge. At this point, it's similar to ClamAV's traditional signatures

Memory consumtion is affected by:
1. Database loading
2. File processing

Both Yara and ClamAV's traditional signatures load everything into memory. That being said, the bigger database is, the more ram they use. Meanwhile the Bytecode signature of ClamAV supposes to be like a single binary. In theory, bytecode signature won't have the huge memory consumption in term of database loading.

The test used 4 signatures to detect Mirai botnet (Yara rule has 1 extra private rule to detect file magic).

To make a better look, I'll use:
1. Yara text based rule with Yara tool
2. Yara compiled rule with Yara tool
3. Logical signature (text file) with clamscan
4. Bytecode signature with clamscan
5. Re-test all signatures with rkcheck

clamscan will use flag `-i` to print matched files only. It's sightly faster than print all results to the terminal. The result is calculated by the tool `time`

**Result**
- **clamav** with **logical signature**. Command `time clamscan -d mirai.ldb ~/Desktop/MalwareLab/LinuxMalwareDetected -i`. Result: `0:05.00 real,	4.75 user,	0.25 sys,	0 amem,	25316 mmem`
- **clamav** with **bytecode signature**. Command `time clamscan -d Mirai.cbc ~/Desktop/MalwareLab/LinuxMalwareDetected -i --bytecode-unsigned`. Result: `0:04.97 real,	4.73 user,	0.23 sys,	0 amem,	25444 mmem`
- **Yara** with **compiled rules**. Command `time yara -C compiled_rule.yac ~/Desktop/MalwareLab/LinuxMalwareDetected`. Result: `0:00.10 real,	1.11 user,	0.06 sys,	0 amem,	68640 mmem`
- **Yara** with **text-based rules**. Command: `time yara rule.yara ~/Desktop/MalwareLab/LinuxMalwareDetected`. Result: `0:00.10 real,	1.11 user,	0.06 sys,	0 amem,	75324 mmem`

**Conclusions**
Yara is a lot faster than ClamAV when it processed files (x50). However, the memory consumpting is huge (3x). Yara doesn't have file parsers. So when user uses Yara to scan huge files in the system, memory exhausted could happend. The scan speed of Yara is impressing though.

**The test's result with rkcheck**
- The time consumption of rkcheck is about 5 secs, similar to ClamAV's result. It's a lot slower than original Yara.
- The memory using **Yara's compiled rules** costs 24mb, while the **Yara's text-based rules** costs 31mb. That's a big number IMO. The result using **ClamAV's bytecode** costs 26mb. The **logical signature** costs 25mb.
- An interesting info: when I tested **rkcheck** with ClamAV's **pre-scan** callback and current **Yara rules** of rkcheck, it took 3 secs to complete the scan. The **post-scan** callback took 5 secs. However, the test with current ruleset made no differences.

**Update the test with rkscan** I've commited a change that pre-check the file's magic before scan. If the header is ELF file, it will call the Yara's scan engine directly. It saves a lot of time scanning with the test condition
- Scan with Yara rules text file `0:00.75 real,   0.71 user,      0.03 sys,       0 amem, 30748 mmem`
- Compiled Yara rules `0:00.75 real,   0.71 user,      0.03 sys,       0 amem, 23456 mmem`
- Full DB scan (same target folder) took `0:02.00 real,   1.95 user,      0.04 sys,       0 amem, 40092 mmem` I assume this is the best optimization I can make for now.

**Final Conclusions**
- There's a huge differences between **compiled Yara rules** and **text-based yara rules**. The scan time of **ClamAV** and **Yara** is massive huge too
- There's no memory consumption tests between **ClamAV's bytecode sigs** and **ClamAV's text-based sig** (yet?). In theory, **bytecode's sigs** should save a lot of memory when the database is huge
- The memory comparison between **ClamAV** and **Yara** included both *database loading* and *file processing*. There's no clue to tell which one is better in term of memory costs. However, I'd give a point to Yara engine because it supports memory scanning on Linux, and the Yara rule is much easier to write. Yara rule engine is much effectives with the modules as well. The point is for the developers / researcher. In real world scenarios, the user should choose the ruleset carefully instead of run and scan *everything*.
- It's really hard to improve the scan time of **rkcheck** because it uses ClamAV to process the files. The memory consumption improvement could be able to do using ClamAV's bytecode signatures. However, it requires real test. And using ClamAV's bytecode sigs also means there's no way to scan Linux's memory for now. If ClamAV supports memory scan (and again, the **bytecode sigs** doesn't have memory exhausted problem), I'd use only some specific Yara's rules to use their modules. String matching rules will use ClamAV's Bytecode engine to save memory.
- Sorry for my bad English and bad markdown fromat

# Feature comparison of some rootkit scanners

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
