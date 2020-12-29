from netmiko import ConnectHandler
from datetime import date
import argparse

# Get information from arguments
parser = argparse.ArgumentParser(description="Add rule to ACP.")

parser.add_argument("-ho", "--ip",
                    help="IP of the ASA of interest", required=True)
parser.add_argument("-po", "--port", type=int, default=22,
                    help="SSH port of the ASA of interest. Default is 22")
parser.add_argument("-u", "--user",
                    help="Username of the FMC of interest", required=True)
parser.add_argument("-p", "--password",
                    help="Password of the FMC of interest", required=True)
parser.add_argument("-s", "--secret", default="Challenge 2 Rule",
                    help="Secret password for ASA. Optional, defaults to ''")

args = parser.parse_args()

# No need for error handling for IP or port, as Netmiko exceptions cover mistaken hostnames and ports

# Device info for Netmiko
cisco_ASA = {
    'device_type': 'cisco_asa',
    'host':   args.ip,
    'username': args.user,
    'password': args.password,
    'port' : args.port,       # optional, defaults to 22
    'secret': args.secret,     # optional, defaults to ''
}

# Connect to the ASA and issue commands.
net_connect = ConnectHandler(**cisco_ASA)
cpu = net_connect.send_command('show cpu')
memory = net_connect.send_command('show memory')
uptime = net_connect.send_command('show version | i up')
net_connect.disconnect()

# Print outputs to file
with open("ASA-outputs-"+date.today().strftime("%Y-%m-%d")+".txt", "w") as writer:

    writer.write("-------------------------------| Device CPU |--------------------------------\n\n")
    writer.write(cpu)
    writer.write("\n\n------------------------------| Device Memory |------------------------------\n\n")
    writer.write(memory)
    writer.write("\n\n------------------------------| Device Uptime |------------------------------\n\n")
    writer.write(uptime)
