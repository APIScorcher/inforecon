
### Cloudflare scan took from https://github.com/christophetd/CloudFlair  Kindly check it out :) ###
import os
import sys
import requests
from shodan import Shodan
import socket
import json
import cloudflare
import nmap

api = Shodan('') # Get your key from https://account.shodan.io


 
if len(sys.argv) < 2:
    print("Usage: python3 " + sys.argv[0] + " <url>")
    sys.exit(1)

target = sys.argv[1]
IPAddr = socket.gethostbyname(target)

os.system('cls' if os.name == 'nt' else 'clear')

print("""
██ ███    ██ ███████  ██████  ██████  ███████  ██████  ██████  ███    ██ 
██ ████   ██ ██      ██    ██ ██   ██ ██      ██      ██    ██ ████   ██ 
██ ██ ██  ██ █████   ██    ██ ██████  █████   ██      ██    ██ ██ ██  ██ 
██ ██  ██ ██ ██      ██    ██ ██   ██ ██      ██      ██    ██ ██  ██ ██ 
██ ██   ████ ██       ██████  ██   ██ ███████  ██████  ██████  ██   ████                                                                         
""")




def getIPInfo():
    try:
        req = requests.get("https://" + target)
    except:
        req = requests.get("http://" + target)

    print(str(req.headers) + "\n")

    print("[*] The IP Address of " + target + " is: " + IPAddr + "\n")

    # ipinfo

    req_two = requests.get("https://ipinfo.io/" + IPAddr + "/json")
    resp_ = json.loads(req_two.text)

    print("[+] Location: " + resp_["loc"])
    print("[+] Region: " + resp_["region"])
    print("[+] City: " + resp_["city"])
    print("[+] Country: " + resp_["country"] + "\n")


def scanPorts():
    choice = input("Would you like to scan for open ports? (Y/N): ")
    if choice == "y" or choice == "Y":
        ports = [21, 22, 23, 25, 53, 80, 110,
                 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

        portScanner = nmap.PortScanner()

        print("Scanning ports...")
        for port in ports:
            portscan = portScanner.scan(target, str(port))
            print("[+] Port", port, "is", portscan['scan']
                  [list(portscan['scan'])[0]]['tcp'][port]['state'])
        print("[+] \nHost", target, "is", portscan['scan']
              [list(portscan['scan'])[0]]['status']['state'])

    else:
        print("\n")

### Cloudflare scan took from https://github.com/christophetd/CloudFlair  Kindly check it out :) ###


def cloudflareScan():
    print("[+] Starting CloudFlare Scan...")
    if not cloudflare.uses_cloudflare(target):
        print("[*] '%s' does not seem to be using CloudFlare" % target)
    else:
        print("[*] '%s' appears to be using CloudFlare" % target)


def shodanLookUp():
    shodanInput = input("Would you like to scan website using Shodan? (Y/N): ")
    if shodanInput == "y" or shodanInput == "Y":
        host = api.host(IPAddr)


        # Print general info
        print("""
        IP: {}
        Organization: {}
        Operating System: {}
        """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

        # Print all banners
        for item in host['data']:
            print("""
            Port: {}
            Banner: {}
            """.format(item['port'], item['data']))



def subDomainEnum():
    print("\n[*] Subdomain Enumeration:")
    list = input("Enter wordlist location: ")
    file = open(list).read() 
    subdomains = file.splitlines()

    print("[*] Started Scanning...")

    for domain in subdomains:
        try:
            urlCheck = f"http://{domain}.{sys.argv[1]}"
        except:
            urlCheck = f"https://{domain}.{sys.argv[1]}"

        try:
            requests.get(urlCheck)
        except  requests.ConnectionError:
            pass
        
        else:
            print("[+] Subdomain Found: ", urlCheck)
    

getIPInfo()
scanPorts()
cloudflareScan()
shodanLookUp()
subDomainEnum()
