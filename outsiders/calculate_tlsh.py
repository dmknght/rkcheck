# Install library from https://github.com/trendmicro/tlsh
import tlsh
import os


# MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/new_Mirai/"
# MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/vbackdoor/"
# MALWARE_DIR = "/mnt/maintain/VirusCollection/vxheavens-2010-05-18/viruses-2010-05-18/"
# MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/Linux-Malware-Samples/"
MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/"


class TlshResult:
  def __init__(self, hash):
    self.hash = hash
    self.count = 1


def append_same_hash(hash, list_results):
  if not list_results:
    return False
  for each_result in list_results:
    if each_result.hash == hash:
      each_result.count += 1
      return True
  return False


def main():
  list_results = []
  for root, dirs, files in os.walk(MALWARE_DIR, topdown=False):
    for name in files:
      full_path = root + name
      if os.path.isfile(full_path):
        newHashObj = TlshResult(tlsh.hash(open(full_path, 'rb').read()))
        if newHashObj.hash == "TNULL":
          # File is not valid (not ELF file?). Ignore
          pass
        elif not append_same_hash(newHashObj.hash, list_results):
          list_results.append(newHashObj)


  for each_hash in list_results:
    print(each_hash.count, each_hash.hash)


def find_hash(hash = "T158923207B7569A9BC55C8B3044F65330F776FC499B332B273218722E1E73B44AE21A98"):
  for root, dirs, files in os.walk(MALWARE_DIR, topdown=False):
    for name in files:
      full_path = root + name
      if os.path.isfile(full_path):
        if hash == tlsh.hash(open(full_path, 'rb').read()):
          print(full_path)


# main()
find_hash()

