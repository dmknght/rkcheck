# What is this
This tool is a combination of Yara and ClamAV to do malware scanning on Linux system. It was made as the idea that rkhunter and chkrootkit need better replacement since both tools check absolute paths exist only.

# More info about this tool
Wiki is at https://github.com/dmknght/rkcheck/wiki

# Roadmaps
- Update the tool with latest ClamAV and Yara engine. Support static build
- Research eBPF so this project can have proper way to detect kernel-land and user-land rootkits

# License, copyright
- Reused Yara engine under BSD-3-Clause.
- Reused ClamAV engine under GPL-2.0
- Reused some Yara rules from Tenable under BSD-3-Clause
- Some rules are having no custom licenses from Lacework Labs, Trend Micro
- Special thank to Nim lang community, ClamAV community, malware researcher Itay Cohen and everbody helped me this project
