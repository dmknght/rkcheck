YRFLAGS = --passL:-lssl --passL:-lcrypto --passL:-lpthread --passL:-lyara
CLFLAGS = --passL:-lclamav
NIMFLAGS = nim c --nimcache:/tmp -d:release --opt:size --passL:-s
STATICFLAG = --passL:-static

all:

build:
	# Generate "build" folder
	mkdir -p build/database
	# Compile and run signature compiler
	$(NIMFLAGS) $(YRFLAGS) --out:build/rkcompiler src/compiler/yr_db_compiler.nim
	# Compile main file
	$(NIMFLAGS) $(CLFLAGS) $(YRFLAGS) --out:build/rkscanner src/rkscanner.nim
	$(NIMFLAGS) --out:build/rkhiddenproc src/tools/unhide_procs.nim

install:
	mkdir -p /usr/share/rkscanner/
	cp -r build/database /usr/share/rkscanner/
	cp build/rkscanner /usr/bin/rkscanner

	chmod +x /usr/bin/rkscanner
	chmod +x /usr/bin/rkcompiler

uninstall:
	rm /usr/bin/rkscanner
	rm -rf /usr/share/rkscanner/

clean:
	rm -rf build/
