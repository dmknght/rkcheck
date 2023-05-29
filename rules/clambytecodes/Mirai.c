VIRUSNAME_PREFIX("Botn.Mirai")
VIRUSNAMES("Generic", "4c36", "9c77", "92a0")
TARGET(6) // ELF file

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(SigGenStr0)
DECLARE_SIGNATURE(SigGenStr1)
DECLARE_SIGNATURE(SigGenStr2)
DECLARE_SIGNATURE(SigGenStr3)
DECLARE_SIGNATURE(SigGenStr4)
DECLARE_SIGNATURE(Sig4c36Str1)
DECLARE_SIGNATURE(Sig4c36Str2)
DECLARE_SIGNATURE(Sig9c77Str)
DECLARE_SIGNATURE(Sig92a0Str)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(SigGenStr0, "6364202f746d70207c7c206364202f7661722f72756e207c7c206364202f6d6e74207c7c206364202f726f6f74207c7c206364202f")
DEFINE_SIGNATURE(SigGenStr1, "6d616b6549505061636b6574")
DEFINE_SIGNATURE(SigGenStr2, "554450524157")
DEFINE_SIGNATURE(SigGenStr3, "73656e64524157")
DEFINE_SIGNATURE(SigGenStr4, "48736872516a7a62536a4873")
DEFINE_SIGNATURE(Sig4c36Str1, "253973202533687520253235355b5e")
DEFINE_SIGNATURE(Sig4c36Str2, "6f616e6163726f616e65")
DEFINE_SIGNATURE(Sig9c77Str, "33316d69703a2573")
DEFINE_SIGNATURE(Sig92a0Str, "34723373206230746e3374")
SIGNATURES_END


bool logical_trigger(void)
{
  if (
      matches(Signatures.SigGenStr0) ||
      matches(Signatures.SigGenStr1) ||
      matches(Signatures.SigGenStr2) ||
      matches(Signatures.SigGenStr3) ||
      matches(Signatures.SigGenStr4) ||
      matches(Signatures.Sig4c36Str1) ||
      matches(Signatures.Sig4c36Str2) ||
      matches(Signatures.Sig9c77Str) ||
      matches(Signatures.Sig92a0Str)
  )
  {
    return true;
  }
  return false;
}

int entrypoint(void)
{
  if (
    count_match(Signatures.SigGenStr0) ||
    count_match(Signatures.SigGenStr1) ||
    count_match(Signatures.SigGenStr2) ||
    count_match(Signatures.SigGenStr3) ||
    count_match(Signatures.SigGenStr4)
  )
  {
    foundVirus("Generic");
  }
  else if (
    count_match(Signatures.Sig4c36Str1) ||
    count_match(Signatures.Sig4c36Str2)
  )
  {
    foundVirus("4c36");
  }
  else if (count_match(Signatures.Sig9c77Str))
  {
    foundVirus("9c77");
  }
  else if (count_match(Signatures.Sig92a0Str))
  {
    foundVirus("92a0");
  }

  return 0;
}
