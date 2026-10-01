"""
This is code written by Nate Montogmery.
This is meant to be a port scanner.
It is followed from the youtube vieo: https://www.youtube.com/watch?v=t9EX2RAUoTU
Although this is updated and uses python 3 and not python 2.
This also has a timeout for sockets.
"""
import socket
import subprocess
import sys
from datetime import datetime

# Clear your screen
subprocess.call('clear', shell=True)

# Ask for input
remoteServer = input("Enter a remote host to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)

#prints the please wait scaning host
print("-" * 60)
print("Please wait, scanning remote host", remoteServerIP)
print("-" * 60)

#The time before scanning
t1 = datetime.now()

try:
    # Scanning ports from 1 to 4999
    for port in range(1, 5000):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  # Prevents the script from hanging too long on closed ports
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print("Port {}: OPEN".format(port))
            service = socket.getservbyport(port)
            print(f"Service: {service}")
        sock.close()

except KeyboardInterrupt:
    print("\nYou pressed Ctrl+C")
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved. Exiting")
    sys.exit()

except socket.error:
    print("Couldn't connect to server")
    sys.exit()

t2 = datetime.now()
total = t2 - t1

print("-" * 60)
print("Scanning Completed in:", total)
print("-" * 60)
