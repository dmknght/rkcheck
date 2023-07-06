VIRUSNAME_PREFIX("Botn.Helios")
VIRUSNAMES("Generic")
TARGET(6) // ELF file

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(str1)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(str1, "426f746e6574204d61646520427920677265656b2e48656c696f73")
SIGNATURES_END


bool logical_trigger(void)
{
  return matches(Signatures.str1);
}

int entrypoint(void)
{
  foundVirus("Generic");
  return 0;
}
