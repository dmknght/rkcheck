#[
  Binding of libtlsh-dev on Debian
  Requires to Compile with cpp instead of c when use Nim compiler
]#

{.pragma: impTlsh, header: "tlsh.h".}
{.passL: "-ltlsh".}

type
  Tlsh {.importcpp: "Tlsh".} = object

# Allow the user to add data in multiple iterations
# void update(const unsigned char* data, unsigned int len);
proc update*(tlsh: Tlsh, data: cstring, len: cuint): cint {.importcpp, impTlsh.}

# To signal the class there is no more data to be added
# void final(const unsigned char* data = NULL, unsigned int len = 0);
proc final*(tlsh: Tlsh, data: cstring = nil, len: cuint = 0): void {.importcpp, impTlsh.}

# To get the hex-encoded hash code
# const char* getHash() const ;
proc getHash*(tlsh: Tlsh): cstring {.importcpp, impTlsh.}

# To get the hex-encoded hash code without allocating buffer in TlshImpl - bufSize should be TLSH_STRING_BUFFER_LEN */
# const char* getHash(char *buffer, unsigned int bufSize) const;
# NOTICE: look like this method is used when the fromTlshStr is called. And the buffer is the variable that contains hash from text
proc getHash*(tlsh: Tlsh, buffer: cstring, size: uint): cstring {.importcpp, impTlsh.}

# To bring to object back to the initial state */
# void reset();
proc reset*(tlsh: Tlsh): void {.importcpp, impTlsh.}

# Calculate difference
# int totalDiff(const Tlsh *, bool len_diff=true) const;
proc totalDiff*(tlsh: Tlsh, compare_hash: ptr Tlsh, len_diff: bool = true): cint {.importcpp, impTlsh.}

# Validate TrendLSH string and reset the hash according to it */
# int fromTlshStr(const char* str);
proc fromTlshStr*(tlsh: Tlsh, data: cstring): cint {.importcpp, impTlsh.}

# Return the version information used to build this library
# static const char *version();
proc version*(tlsh: Tlsh): cstring {.importcpp, impTlsh.}

# TODO if possible, create a library from this, handling calculating hashes from file pointer / file descriptor
when isMainModule:
  var
    t1, t2: Tlsh
    str1: cstring = "Test string hello world"
    str2: cstring = "This string is hello world"

  t1.final(str1, 512)
  t2.final(str2, 512)
  echo t1.getHash()
  echo t2.getHash()
  echo totalDiff(t1, t2.addr)
