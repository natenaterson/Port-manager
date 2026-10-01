import socket
import subprocess
import sys 
from datetime import datetime

#Balnk your screen
subprocess.call('clear', shell=True)

#Ask fro input
remoteServer = input("Enter a remote host to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)

print("_" * 60)
print("Please wait, scanning remote host", remoteServerIP)
print("_" * 60)

tl = datetime.now()

try:
	for port in range (1,5000):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		result = sock.connect_ex((remoteServerIP, port))
		if result == 0:
			print("Port {}:		OPEN".format(port))
		sock.close()
		
except KeyboardInterrupt:
	print("You pressed Ctrl+C")
	sys.exit()
	
except socket.gaierror:
	print("Hostname could not be resolved. Exiting")
	sys.exit()
	
except socket.error:
	print("Couldn't connect to server")
	sys.exit()
	
t2 = datetime.now()

total = t2 - t1

print('Scanning Completed in: ', total)
