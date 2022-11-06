all:

build:
	# Generate "build" folder
	mkdir -p build
	# Compile and run signature compiler
	nim c -r --nimcache:/tmp -d:release --out:build/rkcompiler src/compiler/yr_db_compiler.nim
	# Copy the compiled signatures to build
	cp -r database build/
	# Compile main file
	nim c --nimcache:/tmp -d:release --out:build/rkscanner src/rkscanner.nim

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
