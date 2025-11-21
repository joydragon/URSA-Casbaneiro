#!/usr/bin/env python3

import sys, os
import re, json
import requests, argparse
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def extract_info_from_index(req):
    info = []
    soup = BeautifulSoup(req.content, 'html.parser')
    if soup.title.string.startswith("Index of "):
        res = soup.find_all("a")
        for a in res:
            link = a.get("href")
            if link.startswith("?"):
                continue
            elif a.string == "Parent Directory":
                continue
            info.append({"link":link, "text": a.string, "date" : a.find_next().string, "size": a.find_next().find_next().string})
    return info

def get_urls(domain, mal_type):
    urls = { 
            "muestras": [],
            "logs": [],
            "otros": []
            }
    if mal_type == "URSA":
        urls["muestras"].append("https://" + domain + "/v/")
        urls["logs"].append("https://" + domain + "/g1/lib/")
        urls["logs"].append("https://" + domain + "/g2/lib/")
        urls["logs"].append("https://" + domain + "/g3/lib/")
        urls["logs"].append("https://" + domain + "/g4/lib/")
        urls["logs"].append("https://" + domain + "/g5/lib/")
    elif mal_type == "Casbaneiro":
        urls["logs"].append("https://" + domain + "/w1/downloads/")
        urls["otros"].append("https://" + domain + "/w1/lib/log/")
        urls["otros"].append("https://" + domain + "/w1/_/")
    return urls

def main(domain, mal_type = "URSA", out_file = None):
    result = {
            "muestras": [],
            "logs": [],
            "otros": []
            }

    print("Iniciando revisión de: " + domain)

    s = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)',
        'Language': 'AcAccept-Language: es-CL, es;q=0.9, en-US;q=0.8, en;q=0.7'
    }
    s.headers = headers

    if out_file is None:
        out_file = domain.replace(".","_") + ".json"

    urls = get_urls(domain, mal_type)
    for t in urls:
        for u in urls[t]:
            res = s.get(u)
            if res.status_code == 200:
                print("Encontramos algo en: " + u)
                info = extract_info_from_index(res)
                j = {"url": u, "info": info}
                result[t].append(j)

    f = open(out_file, "w", encoding='utf-8')
    json.dump(result, f, ensure_ascii=False, indent=4)
    f.close()
    print("Terminó la revisión.")
    print("Resultado en archivo: " + out_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='URSA victims and malwares',
                    description='Obtiene links a victimas"',
                    epilog='Ojala que sirva')
    parser.add_argument("-u", "--url", type=str, required=True)
    parser.add_argument("-t", "--type", choices=["U", "u", "URSA", "ursa", "C", "c", "Casbaneiro", "casbaneiro"], default="U")
    parser.add_argument("-o", "--out_file", type=str)
    args = parser.parse_args()

    d = urlparse(args.url)
    if d is not None and d.netloc == "" and d.path != "":
        args.url = d.path
    if d is not None and d.netloc != "":
        args.url = d.netloc
    else:
        print("ERROR en el parseo de URL")
        sys.exit(1)
    
    if args.type in ["U", "u", "URSA", "ursa"]:
        args.type = "URSA"
    elif args.type in ["C", "c", "Casbaneiro", "casbaneiro"]:
        args.type = "Casbaneiro"
    main(args.url, args.type, args.out_file)
