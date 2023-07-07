# Install library from https://github.com/trendmicro/tlsh
import tlsh
import os

MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/msf/"
TEST_SAMPLE = "/home/dmknght/Desktop/MalwareLab/msf/meter1"
HASH_METERPRETER = "T1AED080331B0A51DEDED4023FA5B4599CD77B8977578966310860DC050C096055F52C75"


def calc_tls_hash(path):
  result = tlsh.Tlsh()
  with open(path, 'rb') as f:
    for buf in iter(lambda: f.read(512), b''):
      result.update(buf)
    result.final()

  return result


def main():
  test_hash = tlsh.Tlsh()
  test_hash.fromTlshStr(HASH_METERPRETER)

  for root, dirs, files in os.walk(MALWARE_DIR, topdown=False):
    for name in files:
      full_path = root + name
      new_hash = calc_tls_hash(full_path)
      score = test_hash.diff(new_hash)
      if score < 100:
        print(f"S-Diff: {score} {full_path}")


main()
