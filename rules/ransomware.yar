rule Aris {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "bc1qef3d3ryemlunehdxtx8xvrkdt3w6cgzj8skl2c"
    $2 = "Congrats you have been hit by the ArisLocker so lets talk about recovering your files"
  condition:
    any of them
}

rule ChastityLock {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings:
    $1 = "www.qiuitoy.com"
    $2 = "ransoming %d:%s from %d:%s"
  condition:
    any of them
}

rule Scrypt_a {
  meta:
    author = "Nong Hoang Tu"
    email = "dmknght@parrotsec.org"
    date = "17/11/2021"
  strings: 
    $1 = "All Your Files Have Been Encrypted" nocase
    $2 = "BTC Address:" nocase
    $3 = "UniqueID:" nocase
  condition:
    all of them
}