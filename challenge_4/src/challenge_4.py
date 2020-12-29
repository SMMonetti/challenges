import re
import os

fileName = ""
# Check for txt file on directory. This will be the show tech.
for file in os.listdir("."):
    if file.endswith(".txt"):
        fileName = file
if fileName == "":
    exit("No txt file found. Please add .txt file containing ASA show tech on /src dir.")

dictResults = {
    "platform" : "",
    "version" : "",
    "uptime" : "",
    "serial-number" : ""
}

with open(fileName) as show_tech:
    for line in show_tech:
        if dictResults["version"] == "":
            version = re.match(r"Cisco Adaptive Security Appliance Software Version (\d.+)", line)
            if version:
                dictResults["version"] = version.group(1)
        elif dictResults["uptime"] == "":
            uptime = re.match(r".*up (.+)", line)
            if uptime:
                dictResults["uptime"] = uptime.group(1)
        elif dictResults["platform"] == "":
            platform = re.match(r"Hardware: +(\S+),", line)
            if platform:
                dictResults["platform"] = platform.group(1)
        elif dictResults["serial-number"] == "":
            serial = re.match(r"Serial Number: (.+)", line)
            if serial:
                dictResults["serial-number"] = serial.group(1)
        else:
            # All values have been retrieved from file.
            break

print(dictResults)
