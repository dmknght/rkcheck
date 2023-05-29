# Try ClamAV bytecodes.
To get Clam's Bytecode compiler, just clone the repo `https://github.com/Cisco-Talos/clamav-bytecode-compiler/`
then build `docker build .`
Run it with mounted volumn `docker run -v /home/dmknght/ParrotProjects/rkcheck/rules/:/tmp/signatures -it 7a692a862786 /bin/bash` (use `docker images ls`). There are 2 images. The heavier one is not the image to run
# Why this
The bytecode likely uses less memory. (ClamAV doesn't support scanning processes on Linux though). This is to learn and test ClamAV bytecode sigs only. If it has better performance than Yara, I might replace simple string matching rules