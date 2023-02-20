YRFLAGS = --passL:-lssl --passL:-lcrypto --passL:-lpthread --passL:-lyara
YRFLAGS_STATIC = --passL:-static --passL:-lyara --passL:-pthread --passL:-lcrypto --passL:-lssl --passL:-lmagic --passL:-lbz2 --passL:-lz --passL:-ljansson --passL:-lm
CLFLAGS = --passL:-lclamav
NIMFLAGS = nim c --nimcache:/tmp -d:release --opt:speed --passL:-s

all:

build:
	# Generate "build" folder
	mkdir -p build/database
	# Compile and run signature compiler
	$(NIMFLAGS) $(YRFLAGS) -r --out:build/rkcompiler src/compiler/yr_db_compiler.nim
	# Compile main file
	$(NIMFLAGS) $(CLFLAGS) $(YRFLAGS) --out:build/rkscanmal src/rkscanmal.nim

install:
	mkdir -p /usr/share/rkcheck/
	cp -r build/database /usr/share/rkcheck/
	cp build/rkscanmal /usr/bin/rkscanmal

	chmod +x /usr/bin/rkscanmal

uninstall:
	rm /usr/bin/rkscanmal
	rm -rf /usr/share/rkcheck/

clean:
	rm -rf build/
