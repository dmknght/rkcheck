obj-m += unhide_proc.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	nim c --app:staticLib --noMain client_utils.nim
	gcc -L. -l:libclient_utils.a client.c -o client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean:w
	rm libclient_utils.a client
