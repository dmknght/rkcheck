VIRUSNAME_PREFIX("Botn.Zyxel")
VIRUSNAMES("Generic")
TARGET(6) // ELF file

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(str1)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(str1, "6b696c6c65725f6b696c6c5f62795f706f7274")
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
