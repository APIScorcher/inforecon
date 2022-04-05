
### Cloudflare scan took from https://github.com/christophetd/CloudFlair  Kindly check it out :) ###
import os
import sys
import requests
from shodan import Shodan
import socket
from colorama import Fore
import json
import cloudflare
import nmap

# Get your key from https://account.shodan.io
api = Shodan('')


if len(sys.argv) < 2:
    print("Usage: python3 " + sys.argv[0] + " <url>")
    sys.exit(1)

target = sys.argv[1]
IPAddr = socket.gethostbyname(target)

os.system('cls' if os.name == 'nt' else 'clear')

print(Fore.RED + """
@@@  @@@  @@@  @@@@@@@@   @@@@@@   @@@@@@@   @@@@@@@@   @@@@@@@   @@@@@@   @@@  @@@  
@@@  @@@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@ @@@  
@@!  @@!@!@@@  @@!       @@!  @@@  @@!  @@@  @@!       !@@       @@!  @@@  @@!@!@@@  
!@!  !@!!@!@!  !@!       !@!  @!@  !@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!  
!!@  @!@ !!@!  @!!!:!    @!@  !@!  @!@!!@!   @!!!:!    !@!       @!@  !@!  @!@ !!@!  
!!!  !@!  !!!  !!!!!:    !@!  !!!  !!@!@!    !!!!!:    !!!       !@!  !!!  !@!  !!!  
!!:  !!:  !!!  !!:       !!:  !!!  !!: :!!   !!:       :!!       !!:  !!!  !!:  !!!  
:!:  :!:  !:!  :!:       :!:  !:!  :!:  !:!  :!:       :!:       :!:  !:!  :!:  !:!  
 ::   ::   ::   ::       ::::: ::  ::   :::   :: ::::   ::: :::  ::::: ::   ::   ::  
:    ::    :    :         : :  :    :   : :  : :: ::    :: :: :   : :  :   ::    :                                                                         
\n""")


def getIPInfo():
    try:
        global req
        req = requests.get("https://" + target)
    except:
        req = requests.get("http://" + target)

    print(Fore.GREEN + str(req.headers) + "\n")

    print("[*] The IP Address of " + target + " is: " + IPAddr + "\n")

    # ipinfo

    req_two = requests.get("https://ipinfo.io/" + IPAddr + "/json")
    resp_ = json.loads(req_two.text)

    print("[+] Location: " + resp_["loc"])
    print("[+] Region: " + resp_["region"])
    print("[+] City: " + resp_["city"])
    print("[+] Country: " + resp_["country"] + "\n")


def scanPorts():
    choice = input(Fore.RED + "Would you like to scan for open ports? (Y/N): ")
    if choice in ("y", "Y"):
        ports = [21, 22, 23, 25, 53, 80, 110,
                 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

        portScanner = nmap.PortScanner()

        print(Fore.RED + "Scanning ports...")
        for port in ports:
            portscan = portScanner.scan(target, str(port))
            print(Fore.GREEN + "[+] Port", port, "is", portscan['scan']
                  [list(portscan['scan'])[0]]['tcp'][port]['state'])
    else:
        print("\n")

### Cloudflare scan took from https://github.com/christophetd/CloudFlair  Kindly check it out :) ###


def cloudflareScan():
    print(Fore.RED + "[+] Starting CloudFlare Scan...")
    if not cloudflare.uses_cloudflare(target):
        print(Fore.GREEN + "[*] '%s' does not seem to be using CloudFlare" % target)
    else:
        print(Fore.GREEN + "[*] '%s' appears to be using CloudFlare" % target)


def shodanLookUp():
    shodanInput = input(Fore.RED + "\nWould you like to scan website using Shodan? (Y/N): ")
    if shodanInput in ("y", "Y"):
        host = api.host(IPAddr)

        # Print general info
        print(Fore.GREEN + """
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
    subdomainInput = input(
        Fore.RED + "\nWould you like to start a subdomain enumeration? (Y/N): ")
    if subdomainInput in ("y", "Y"):
        print(Fore.RED + "\n[*] Subdomain Enumeration:")
        list = input("Enter wordlist location: ")
        file = open(list).read()
        subdomains = file.splitlines()

        print(Fore.GREEN + "[*] Started Scanning...")

        for domain in subdomains:
            try:
                urlCheck = f"http://{domain}.{sys.argv[1]}"
            except:
                urlCheck = f"https://{domain}.{sys.argv[1]}"

            try:
                requests.get(urlCheck)
            except requests.ConnectionError:
                pass

            else:
                print(Fore.GREEN + "[+] Subdomain Found: ", urlCheck)
    else:
        print("")

def directoryFuzz():
    directoryInput = input(Fore.RED + "Would you like to fuzz directories? (Y/N): ")
    if directoryInput in ("y", "Y"):
        print("[*] Directory Fuzzing: ")
        dirWordlist = input("Enter the wordlist: ")
        try:
            dirWordlist = open(dirWordlist,"rb")
            print(Fore.GREEN + "[+] Starting Directory Fuzzing")
            for path in dirWordlist.readlines():
                path = path.strip().decode("utf-8")
                try:
                    urlpath = "http://"+target+"/"+path
                except:
                    urlpath = "https://"+target+ "/"+path
                r = requests.get(urlpath)
                if r.status_code != 404:
                    print(Fore.GREEN + "[+] {} -> {}".format(r.status_code, urlpath))
        except Exception as e:
            print(Fore.RED + "Error Occured: {}".format(e))
        
    else:
        print("\n")


getIPInfo()
scanPorts()
cloudflareScan()
shodanLookUp()
subDomainEnum()
directoryFuzz()
