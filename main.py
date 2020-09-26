import requests
from bs4 import BeautifulSoup
from random import choice
import html5lib
import ipaddress
import cfscrape as cf
import whois
import socket
import re

def proxyRange():
    global proxy_dict
    proxy_dict = {}
    start_ip = ipaddress.IPv4Address(input("Enter Start IP: "))
    end_ip = ipaddress.IPv4Address(input("Enter End IP: "))
    for ip_int in range(int(start_ip), int(end_ip)):
        proxy_dict[str(ipaddress.IPv4Address(ip_int))] = None
    finalURL(proxy_dict)




def randAccessKey():
    list = open('keys.txt').readlines()
    empty = []
    for x in list:
        empty.append(x.strip())
    return choice(empty)

###################################################################

def finalURL(proxyDict):
    for x in proxy_dict.keys():
        f = open(f"{x}.txt", 'w+')
        proxy_dict[x] = f"http://api.scrapestack.com/scrape?access_key={randAccessKey()}&url=https://api.hackertarget.com/reverseiplookup/?q={x}"
    domain_list(proxy_dict)

####################################################################

def domain_list(proxy_dict):
    s = cf.create_scraper()
    global domain_dict
    domain_dict = {}

    for x in proxy_dict.keys():
        domain_dict[x] = s.get(proxy_dict[x]).text.split('\n')
    main(domain_dict)


def main(domain_dict):
    pattern = '[a-zA-Z0-9]+(?:.[a-zA-Z]+)+'
    print(domain_dict)
    for x in domain_dict.keys():
        r = open(f"{x}.txt", 'r+')
        for i in range(len(domain_dict[x])):
            url = domain_dict[x][i]
            if url != f'No DNS A records found for {x}':
                print('Found')
                try:
                    res = whois.whois(url)
                    r.write(f"\n======================================================= INFORMATION FOR {url} =======================================================\n")
                    r.write("Domain Names - " + str(res.domain_name))
                    try:
                        r.write("\nCreation Date - " + str(res.creation_date[0].strftime("%d %B, %Y")))
                    except:
                        r.write("\nCreation Date - " + str(res.creation_date.strftime("%d %B, %Y")))
                    finally:
                        r.write("\nRegistrar - " + str(res.registrar))
                        r.write("\nCountry - " + str(res.country))
                        r.write("\nWhoIs Server - " + str(res.whois_server))
                        r.write("\nName Server - " + str(res.name_servers))
                        r.write("\n\n")
                        i+=1
                except:
                    pass
            else:
                r.write("NO URL's")
                print("NOT FOUND")
                i+=1

    
print(proxyRange())


"""
READ THIS

NEED TO ADD DICT IMPLEMENTATION TO SEE WHICH IP gets WHAT URLs
"""