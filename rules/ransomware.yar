include "rules/magics.yar"


rule Buhti_Generic {
  // https://www.hybrid-analysis.com/yara-search/results/253e29c1998bdf14e711bf2873a464db7ae59d9551e4fdee754e7abe27b56551
  strings:
    $ = "Welcome to buhtiRansom" fullword ascii
    $ = "https://satoshidisk.com/pay/CHfZ5r" fullword ascii
  condition:
    elf_magic and all of them
}


// rule Aris_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "bc1qef3d3ryemlunehdxtx8xvrkdt3w6cgzj8skl2c"
//     $2 = "Congrats you have been hit by the ArisLocker so lets talk about recovering your files"
//   condition:
//     all of them
// }

// rule ChastityLock_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "www.qiuitoy.com" nocase
//     $2 = "ransoming %d:%s from %d:%s"
//   condition:
//     any of them
// }

// rule Scrypt_Generic {
//   meta:
//     author = "Nong Hoang Tu"
//     email = "dmknght@parrotsec.org"
//     date = "17/11/2021"
//   strings:
//     $1 = "All Your Files Have Been Encrypted"
//     $2 = "BTC Address:"
//     $3 = "UniqueID:"
//   condition:
//     all of them
// }
