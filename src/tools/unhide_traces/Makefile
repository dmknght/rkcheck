obj-m += rkkern_unhide.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	nim c --app:staticLib --gc:none --noMain client.nim
	gcc -L. rkcheck_unhide.c -o client -l:libclient.a

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean:w
	rm libclient.a rkcheck_unhide
