YR_DEPS = --passL:-lyara --passL:-pthread --passL:-lcrypto --passL:-lssl --passL:-lmagic --passL:-lbz2 --passL:-lz --passL:-ljansson --passL:-lm --passL:-llzma --passL:-lpthread --passL:-lzstd
CLAM_DEPS = --passL:-lclamav
NIM_CC = nim c --nimcache:build/nimcache/ -d:release --opt:speed --passL:-s
# Add this when want to build static file. On Debian, ClamAV has no static lib so it's impossible to use
BUILD_FLAGS = --passL:-static

.PHONY: build

all: build install

mktmp:
	# Create build folder and db
	mkdir -p build/release/databases
	# Create tmp folder for cache
	mkdir -p build/nimcache

signatures: mktmp
	# Compile Yara signatures
	$(NIM_CC) $(YR_DEPS) -r --out:build/nimcache/rkcompiler src/compiler/yr_db_compiler.nim

build: signatures
	# Compile main file
	$(NIM_CC) $(CLAM_DEPS) $(YR_DEPS) --out:build/release/rkscanmal src/rkscanmal.nim

install:
	mkdir -p /usr/share/rkcheck/
	cp -r build/release/databases /usr/share/rkcheck/
	cp build/release/rkscanmal /usr/bin/rkscanmal

	chmod +x /usr/bin/rkscanmal

uninstall:
	rm /usr/bin/rkscanmal
	rm -rf /usr/share/rkcheck/

clean:
	rm -rf build/
