# What is this
This tool is a combination of Yara and ClamAV to do malware scanning on Linux system. It was made as the idea that rkhunter and chkrootkit need better replacement since both tools check absolute paths exist only.

# More info about this tool
Wiki is at https://github.com/dmknght/rkcheck/wiki

# Roadmaps
- Be able to scan on any Linux system (architecture compatible) without installing dependencies
- Improve detection of user-land rootkit
- Research kernel-land rootkit detection

# License, copyright
- Reused Yara engine under BSD-3-Clause.
- Reused ClamAV engine under GPL-2.0
- Reused some Yara rules from Tenable under BSD-3-Clause
- Some rules are having no custom licenses from Lacework Labs, Trend Micro
- Special thank to Nim lang community, ClamAV community, malware researcher Itay Cohen and everbody helped me this project
- Reuse code from https://github.com/mempodippy/detect_preload/ to detect user-land rootkit's hijacked functions
