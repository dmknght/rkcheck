all:

build:
	# Generate "build" folder
	mkdir -p build/database
	# Compile and run signature compiler
	nim c -r --nimcache:/tmp -d:release --passL:-lssl --passL:-lcrypto --passL:-lpthread --passL:-lm --passL:-lyara --out:build/rkcompiler src/compiler/yr_db_compiler.nim
	# Compile main file
	nim c --nimcache:/tmp -d:release --passL:-lclamav --passL:-lssl --passL:-lcrypto --passL:-lpthread --passL:-lm --passL:-lyara --out:build/rkscanner src/rkscanner.nim
	nim c --nimcache:/tmp -d:release --out:build/rkhiddenproc src/tools/unhide_procs.nim

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
