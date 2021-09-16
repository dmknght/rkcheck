"""
Generate yara rules from ossec config file
https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf
NOTE: This script doesn't handle syntax problem in file name which converts to rules.
Developer must edit rule names manually
"""

import json
data = open("ossec.json").read()
data = json.loads(data)


def make_rules():
  final_rule = ""
  for section, values in data["queries"].items():
    rule = "  meta:\n"
    rule += "    author = \"Nong Hoang Tu\"\n"
    rule += "    email = \"dmknght@parrotsec.org\"\n"
    rule += "    description = \"Automation Yara rule generated from ossec-rootkit.conf\"\n"
    rule += "    url = \"https://github.com/osquery/osquery/blob/master/packs/ossec-rootkit.conf\"\n"
    rule += "  condition:\n"
    rule = f"rule {section}" + " {\n" + rule
    paths = values["query"].split("(")[1].split(")")[0].replace("'", "").split(", ")
    rule += f"    file_path == \"{paths[0]}\""
    if len(paths) != 0:
      for path in paths[1:]:
        rule += f" or file_path == \"{path}\""
    rule += "\n}\n"
  
    final_rule += rule + "\n"
  return final_rule

print(make_rules())
