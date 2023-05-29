VIRUSNAME_PREFIX("Trjn.PingPong")
VIRUSNAMES("Generic")
TARGET(6) // ELF file

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(sdb_to_inittab)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(sdb_to_inittab, "6563686f2022747362643a323334353a7265737061776e3a2573202d6622203e3e202f6574632f696e697474616200696e6974")
SIGNATURES_END


bool logical_trigger(void)
{
  return matches(Signatures.sdb_to_inittab);
}

int entrypoint(void)
{
  foundVirus("Generic");
  return 0;
}
