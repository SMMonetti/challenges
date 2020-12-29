import argparse
import requests
import re
import time
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

# Suppress warning for SSL certificate
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# Get information from arguments
parser = argparse.ArgumentParser(description="Add rule to ACP.")

parser.add_argument("-ho", "--ip",
                    help="IP of the FMC of interest (Optional: can include port with format {IP}:{port})", required=True)
parser.add_argument("-u", "--user",
                    help="Username of the FMC of interest", required=True)
parser.add_argument("-p", "--password",
                    help="Password of the FMC of interest", required=True)
parser.add_argument("-r", "--rule", default="Challenge 2 Rule",
                    help="Rule name for ACP of FMC")

args = parser.parse_args()


# Check IP is valid
if not re.match(r"^(2[0-4]\d|25[0-5]|1?\d{1,2})\.(2[0-4]\d|25[0-5]|1?\d{1,2})\.(2[0-4]\d|25[0-5]|1?\d{1,2})\.(2[0-4]\d|25[0-5]|1?\d{1,2})(:(6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5]|([0-5]?)\d\d\d\d|\d{1,4}))?$", str(args.ip)):
    exit("IP is not valid. Exiting script.")

# Base URL for calls and access credentials
URL = "https://" + args.ip + "/api"

data = {"grant_type": "password"}

# POST token (default time as this is a short process), and include received token on header.
r = requests.post(url=URL+"/fmc_platform/v1/auth/generatetoken", verify=False, auth=HTTPBasicAuth(args.user, args.password))

accesstoken = r.headers["X-auth-access-token"]
DOMAIN_UUID = r.headers["DOMAIN_UUID"]
headers = {'Content-Type': 'application/json', 'x-auth-access-token': accesstoken}
URL = URL+"/fmc_config/v1/domain/"+DOMAIN_UUID

# GET list of devices and select device.
r = requests.get(url=URL+"/devices/devicerecords", headers=headers, verify=False)
print("Available Devices:")
UUIDs = []
i = 0
for item in r.json()["items"]:
    print(str(i) + ") " + item["name"])
    UUIDs.append(item["id"])
    i+=1
option = int(input("Select a device: "))
deviceID = UUIDs[option]

# GET the ACP that is installed on the selected device
AccessPolicyID = ""
AccessPolicyName = ""
breakLoop = False
r = requests.get(url=URL+"/policy/accesspolicies", headers=headers, verify=False).json()
for item in r["items"]:
    r = requests.get(url=URL + "/assignment/policyassignments/"+item["id"], headers=headers, verify=False).json()

    if "targets" in r:
        for target in r["targets"]:
            if target["id"] == deviceID:
                AccessPolicyID = item["id"]
                AccessPolicyName = item["name"]
                breakLoop = True
                break

    if breakLoop:
        break

# Display rule that will be created
payload = "{\r\n  \"sourceNetworks\": {\r\n    \"objects\": [\r\n      {\r\n        \"type\": \"NetworkGroup\",\r\n        \"overridable\": false,\r\n        \"id\": \"15b12b14-dace-4117-b9d9-a9a7dcfa356f\",\r\n        \"name\": \"IPv4-Private-All-RFC1918\"\r\n      }\r\n    ]\r\n  },\r\n  \"sendEventsToFMC\": false,\r\n  \"enableSyslog\": false,\r\n  \"vlanTags\": {},\r\n  \"logFiles\": false,\r\n  \"logBegin\": false,\r\n  \"logEnd\": false,\r\n  \"variableSet\": {\r\n    \"name\": \"Default Set\",\r\n    \"id\": \"76fa83ea-c972-11e2-8be8-8e45bb1343c0\",\r\n    \"type\": \"VariableSet\"\r\n  },\r\n  \"destinationPorts\": {\r\n    \"objects\": [\r\n      {\r\n        \"type\": \"ProtocolPortObject\",\r\n        \"protocol\": \"TCP\",\r\n        \"overridable\": false,\r\n        \"id\": \"1834e5f0-38bb-11e2-86aa-62f0c593a59a\",\r\n        \"name\": \"Bittorrent\"\r\n      }\r\n    ]\r\n  },\r\n  \"action\": \"BLOCK_RESET\",\r\n  \"type\": \"AccessRule\",\r\n  \"enabled\": true,\r\n  \"name\": \""+args.rule+"\"\r\n}"
print("Installing rule with default values:")

print(args.rule + " | Action: BLOCK_RESET | Log Begin: False | Log End: False\n")
print(payload)

# POST rule to the ACP
r = requests.post(url=URL+"/policy/accesspolicies/"+AccessPolicyID+"/accessrules", headers=headers, data=payload, verify=False)


# Deploy configuration

# Get list of deployable devices and verify there are pending changes for the selected device
r = requests.get(url=URL+"/deployment/deployabledevices?expanded=true", headers=headers, verify=False).json()

# Verify if there are any pending deployments.
if 'items' in r:
    for item in r["items"]:
        if item["device"]["id"] == deviceID and item["canBeDeployed"]:
            # Deploy to device
            payload = "{\r\n    \"type\": \"DeploymentRequest\",\r\n    \"version\": \""+item["version"]+"\",\r\n    \"forceDeploy\": true,\r\n    \"ignoreWarning\": true,\r\n    \"deviceList\":[\r\n    \""+deviceID+"\"\r\n    ]\r\n}"
            r = requests.post(url=URL+"/deployment/deploymentrequests", headers=headers, data=payload, verify=False)
            print("Deploying to device...\n")
else:
    # No pending deployments.
    print("No pending deployments for selected device.")

# monitor deployment
r = requests.get(url=URL+"/deployment/deployabledevices?expanded=true", headers=headers, verify=False).json()
# Monitor deployment
if 'items' in r:
    for item in r["items"]:
        if item["device"]["id"] == deviceID and not item["upToDate"]:
            # Deployment is ongoing
            deploymentFinished = False
else:
    deploymentFinished = True

while (not deploymentFinished):
    time.sleep(3)
    r = requests.get(url=URL + "/deployment/deployabledevices?expanded=true", headers=headers, verify=False).json()
    if 'items' in r:
        for item in r["items"]:
            if item["device"]["id"] == deviceID and not item["upToDate"]:
                deploymentFinished = False
                if item["canBeDeployed"]:
                    exit("Deployment failed. Please verify configuration on FMC")
                break
    else:
        deploymentFinished = True
        print("Deployment has finished.\n")


# Display ACP

r = requests.get(url=URL+"/policy/accesspolicies/"+AccessPolicyID+"/accessrules", headers=headers, verify=False).json()
print("Access Control Policy: " + AccessPolicyName)

# Format rules and print contents
for item in r["items"]:
    r = requests.get(url=URL + "/policy/accesspolicies/" + AccessPolicyID + "/accessrules/" + item["id"], headers=headers, verify=False).json()
    print(item["name"] + " | Action: " + r["action"] + " | Log Begin: " + str(r["logBegin"]) + " | Log End: " + str(r["logEnd"]))

