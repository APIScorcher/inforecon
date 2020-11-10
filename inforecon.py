import sys
import requests
import socket
import json
import nmap


if len(sys.argv) < 2:
    print("Usage: python3 " + sys.argv[0] + " <url>")
    sys.exit(1)

target = sys.argv[1]

def getIPInfo():
    try:
        req = requests.get("https://" + target)
    except:
        req = requests.get("http://" + target)

    print(str(req.headers) + "\n")

    getHostBy = socket.gethostbyname(target)
    print("The IP Address of " + target + " is: " + getHostBy + "\n")

    # ipinfo

    req_two = requests.get("https://ipinfo.io/" + getHostBy + "/json")
    resp_ = json.loads(req_two.text)

    print("Location: " + resp_["loc"])
    print("Region: " + resp_["region"])
    print("City: " + resp_["city"])
    print("Country: " + resp_["country"] + "\n")


def scanPorts():
    choice = input("Would you like to scan for open ports? (Y/N): ")
    if choice == "Y":
        ports = [21, 22, 23, 25, 53, 80, 110,
                 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

        portScanner = nmap.PortScanner()

        print("Scanning ports...")
        for port in ports:
            portscan = portScanner.scan(target, str(port))
            print("Port",port,"is",portscan['scan'][list(portscan['scan'])[0]]['tcp'][port]['state']) 

        print("\nHost",target,"is",portscan['scan'][list(portscan['scan'])[0]]['status']['state'])

    else:
        print("\nExiting...")

getIPInfo()
scanPorts()