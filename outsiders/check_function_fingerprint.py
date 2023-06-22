import rzpipe # Using rizin framework. Replace with r2pipe for radare2
import json
import hashlib
import os


class BinaryMetadata:
  def __init__(self, path: str):
    self.pipe = rzpipe.open(path)
    self.bin_path = path
    self.analysis_funcs()

  def analysis_funcs(self):
    """
      Analysis the current binary to get function names
    """
    self.pipe.cmd("aac")

  def get_function_sum(self):
    """
      Get function calls from a function using Rizin, then generate checksum
    """
    data = self.pipe.cmd("aflmj")

    for each_func_call in json.loads(data):
      list_func_call = []
      for call_func in each_func_call["calls"]:
        list_func_call.append(call_func["name"])

      call_sum = hashlib.md5("\n".join(sorted(list_func_call)).encode()).hexdigest()
      yield call_sum, each_func_call['name']


def find_simi(dir: str):
  for root, dirs, files in os.walk(dir):
    for file in files:
      path = root + file
      analysis = BinaryMetadata(path)
      for checksum, name in analysis.get_function_sum():
        if checksum in ("5caaee57766e657a9662d01a45a9c2ec", "795c7294ae8d72d57ea5756867dc86a4", "795c7294ae8d72d57ea5756867dc86a4", "c59425f0f7e5192422d393b28cfb99ea", "cdfc6520ff61969c374564240a120c2e"):
          print(f"Detected func call: {name}")
          print(f"Checksum: {checksum}")
          print(f"File: {path}")

# # Checksum: 5caaee57766e657a9662d01a45a9c2ec Func: sym.processCmd
# x = BinaryMetadata("/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/eef8b97feeca17f7aa0037e98b4d53fc0f07dc8fe80b195c26ef087ab4334955_detected_detected")
# for checksum, name in x.get_function_sum():
#   print(f"Md5: {checksum} Func: {name}")

print("Find if we can find similar functions in malicious samples")
find_simi("/home/dmknght/Desktop/MalwareLab/LinuxMalwareDetected/")
# print("\nFind if we have simil signature in whitelist dir")
# find_simi("/usr/bin/")