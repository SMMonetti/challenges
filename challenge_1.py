import re
import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress warning for SSL certificate.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# Get information from arguments.
parser = argparse.ArgumentParser(description="Display the amount of free, used, and total disk using the FDM's API.")

# Need to add choices to restric input from user https://docs.python.org/3/howto/argparse.html
parser.add_argument("-ho", "--ip",
                    help="IP of the FTD of interest A.B.C.D (Optional: can include port with format {IP}:{port})", required=True)
parser.add_argument("-u", "--user",
                    help="Username of the FTD of interest", required=True)
parser.add_argument("-p", "--password",
                    help="Password of the FTD of interest", required=True)
parser.add_argument("-v", "--version", type=int, default=5,
                    help="API version number of the FDM (Default is 5 for FTD 6.6)", required=True)


args = parser.parse_args()

# Check IP is valid and version
if not re.match(r"^(2[0-4]\d|25[0-5]|1?\d{1,2})\.(2[0-4]\d|25[0-5]|1?\d{1,2})\.(2[0-4]\d|25[0-5]|1?\d{1,2})\.(2[0-4]\d|25[0-5]|1?\d{1,2})(:(6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]|([0-5]?)\d\d\d\d|\d{1,4}))?$", str(args.ip)):
    exit("IP is not valid. Exiting script.")
if args.version<1 or args.version>6:
    exit("Version is not valid. Valid version values are (1,2,3,4,5,6).")

# Base URL for calls and access credentials
URL = "https://" + args.ip + "/api/fdm/v"+str(args.version)

data = {
  "grant_type": "password",
  "username": args.user,
  "password": args.password
}


# POST token (default time as this is a short process), and include received token on header.
r = requests.post(url=URL+"/fdm/token", data=data, verify=False).json()
# Check if request was successful
if not 'access_token' in r:
    exit("Unable to succesfully authenticate. Check URL and credentials: \nResponse: "+str(r)+"\nURL: "+URL+"/fdm/token")

token = r['access_token']
headers = {"Authorization": "Bearer "+token}


# GET disk usage, and print values obtained.
r = requests.get(url=URL+"/operational/diskusage/default", headers=headers, verify=False).json()

print("\nDisk space calculated in 512-byte blocks:")
print("Free: " + str(r["free"]))
print("Used: " + str(r["used"]))
print("Total: " + str(r["total"]))