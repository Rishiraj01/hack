#!/usr/bin/python3
import nmap
import pprint
import socket
import requests
import ssl
from pprint import pformat

nm=nmap.PortScanner()
host = input('Enter website to be scanned : ')
ip_addr = socket.gethostbyname(host)
context = ssl.create_default_context()
with socket.create_connection((host, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as ssock:
        print("TLS Version: ",ssock.version())
nm.scan(ip_addr, '21-443','-sS')
print('Operating System: ')
data=nm.scan(ip_addr, arguments="-O")['scan'][ip_addr]['osmatch'][1]
result = '\n'.join(f'{key}: {value}' for key, value in data.items())
print(result)



response = requests.get(f'https://ipapi.co/{ip_addr}/json/').json()
location_data = {
        "Ip": ip_addr,
        "City": response.get("city"),
        "Region": response.get("region"),
        "Country": response.get("country_name")
    }
print('\n'.join(f'{key}: {value}' for key, value in location_data.items()))

for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)
        lport = nm[host][proto].keys()

        for port in lport:
                print('port : %s\tstate : %s\tservice : %s' % (port, nm[host][proto][port]['state'],socket.getservbyport(port)))