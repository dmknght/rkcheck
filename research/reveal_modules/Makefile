obj-m += reveal_modules.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	nim c --app:staticLib --gc:none --noMain client.nim
	gcc -L. client.c -o client -l:libclient.a

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean:w
	rm libclient.a client
