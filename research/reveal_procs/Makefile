obj-m += unhide_proc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	nim c --app:staticLib --noMain client.nim
	gcc -L. -l:libclient.a client.c -o client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean:w
	rm libclient.a client
