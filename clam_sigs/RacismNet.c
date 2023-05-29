VIRUSNAME_PREFIX("Botn.RacismNet")
VIRUSNAMES("41fa")
TARGET(6) // ELF file

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(str1)
DECLARE_SIGNATURE(str2)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(str1, "52616369736d4e657439")
DEFINE_SIGNATURE(str2, "424f544b494c4c")
SIGNATURES_END


bool logical_trigger(void)
{
  return matches(Signatures.str1) && matches(Signatures.str2);
}

int entrypoint(void)
{
  foundVirus("41fa");
  return 0;
}
