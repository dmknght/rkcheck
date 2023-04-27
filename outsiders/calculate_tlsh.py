# Install library from https://github.com/trendmicro/tlsh
import tlsh
import os


MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/new_Mirai/"
# MALWARE_DIR = "/home/dmknght/Desktop/MalwareLab/vbackdoor/"


class TlshResult:
  def __init__(self, hash, file):
    self.hash = hash
    self.files = [file]


def append_same_hash(hash, file, list_results):
  if not list_results:
    return False
  for each_result in list_results:
    if each_result.hash == hash:
      each_result.files.append(file)
      return True
  return False


def main():
  list_results = []
  for root, dirs, files in os.walk(MALWARE_DIR, topdown=False):
    for name in files:
      full_path = root + name
      if os.path.isfile(full_path):
        newHashObj = TlshResult(tlsh.hash(open(full_path, 'rb').read()), full_path)
        if not append_same_hash(newHashObj.hash, full_path, list_results):
          list_results.append(newHashObj)



  for each_hash in list_results:
    print(len(each_hash.files), each_hash.hash)

main()

