#[
  Binding of libtlsh-dev on Debian
  Requires to Compile with cpp instead of c when use Nim compiler
]#

{.pragma: impTlsh, header: "tlsh.h".}
{.passL: "-ltlsh".}

type
  Tlsh {.importcpp: "Tlsh".} = object

# A "hack" to create "new" binding
# https://nim-lang.org/docs/manual.html#implementation-specific-pragmas-importcpp-pragma
proc tlsh_new*[T](x: T): ptr T {.importcpp: "(new '*0#@)", nodecl.}
proc TlshObj*(): Tlsh {.importcpp: "Tlsh(@)".}
proc tlsh_free*(tlsh: ptr Tlsh) {.importcpp: "#.~Tlsh()".}

# Allow the user to add data in multiple iterations
# void update(const unsigned char* data, unsigned int len);
proc update*(tlsh: ptr Tlsh; data: cstring; len: cuint): cint {.importcpp, impTlsh.}

# To signal the class there is no more data to be added
# void final(const unsigned char* data = NULL, unsigned int len = 0);
proc final*(tlsh: ptr Tlsh; data: cstring = nil; len: cuint = 0): void {.importcpp, impTlsh.}

# To get the hex-encoded hash code
# const char* getHash() const ;
proc getHash*(tlsh: ptr Tlsh): cstring {.importcpp, impTlsh.}

# To get the hex-encoded hash code without allocating buffer in TlshImpl - bufSize should be TLSH_STRING_BUFFER_LEN */
# const char* getHash(char *buffer, unsigned int bufSize) const;
proc getHash*(tlsh: ptr Tlsh, buffer: cstring, size: uint): cstring {.importcpp, impTlsh.}

# To bring to object back to the initial state */
# void reset();
proc reset*(tlsh: ptr Tlsh): void {.importcpp, impTlsh.}

# Calculate difference
# int totalDiff(const Tlsh *, bool len_diff=true) const;
proc totalDiff*(tlsh: ptr Tlsh, len_diff: bool = true): cint {.importcpp, impTlsh.}

# Validate TrendLSH string and reset the hash according to it */
# int fromTlshStr(const char* str);
proc fromTlshStr*(tlsh: ptr Tlsh, compare_hash: ptr Tlsh, data: cstring): cint {.importcpp, impTlsh.}

# Return the version information used to build this library
# static const char *version();
proc version*(tlsh: ptr Tlsh): cstring {.importcpp, impTlsh.}

var
  vtlsh = tlsh_new TlshObj()

var
  myData: cstring = "aaaa"

echo vtlsh.version()
# discard vtlsh.update(myData, cuint(myData.len))
# vtlsh.final()
# echo vtlsh.getHash()
echo vtlsh.getHash(myData, cuint(myData.len))
vtlsh.tlsh_free()