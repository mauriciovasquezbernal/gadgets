from scapy.all import *

# Define the DNS request packet
dns_request = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="www.example.com"))

# Send the DNS request packet and receive the response
dns_response = sr1(dns_request, verbose=0)

# Print the DNS response
if dns_response:
    dns_response.show()
else:
    print("No response received.")