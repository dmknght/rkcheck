rule Aris_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = { 62 63 31 71 65 66 33 64 33 72 79 65 6D 6C 75 6E 65 68 64 78 74 78 38 78 76 72 6B 64 74 33 77 36 63 67 7A 6A 38 73 6B 6C 32 63 } // "bc1qef3d3ryemlunehdxtx8xvrkdt3w6cgzj8skl2c"
    $2 = { 43 6F 6E 67 72 61 74 73 20 79 6F 75 20 68 61 76 65 20 62 65 65 6E 20 68 69 74 20 62 79 20 74 68 65 20 41 72 69 73 4C 6F 63 6B 65 72 20 73 6F 20 6C 65 74 73 20 74 61 6C 6B 20 61 62 6F 75 74 20 72 65 63 6F 76 65 72 69 6E 67 20 79 6F 75 72 20 66 69 6C 65 73 } // "Congrats you have been hit by the ArisLocker so lets talk about recovering your files"
  condition:
    any of them
}

rule ChastityLock_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = { 77 77 77 2E 71 69 75 69 74 6F 79 2E 63 6F 6D } // "www.qiuitoy.com"
    $2 = { 72 61 6E 73 6F 6D 69 6E 67 20 25 64 3A 25 73 20 66 72 6F 6D 20 25 64 3A 25 73 } // "ransoming %d:%s from %d:%s"
  condition:
    any of them
}

rule Scrypt_Generic {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings: 
    $1 = { 41 6C 6C 20 59 6F 75 72 20 46 69 6C 65 73 20 48 61 76 65 20 42 65 65 6E 20 45 6E 63 72 79 70 74 65 64 } // "All Your Files Have Been Encrypted"
    $2 = { 42 54 43 20 41 64 64 72 65 73 73 3A } // "BTC Address:"
    $3 = { 55 6E 69 71 75 65 49 44 3A } // "UniqueID:"
  condition:
    all of them
}