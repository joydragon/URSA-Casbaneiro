#!/usr/bin/bash
import os
import argparse

def decode(texto, llave):
    key = ord(texto[0])-65
    res = texto[1:]
    final = ""

    while len(res)>0:
        v1 = ord(res[0]) - 65
        v2 = ord(res[1]) - 65
        final += chr( v1*25 + v2 - key - int(llave) )
        res = res[2:]
    return final

def decode_file(filename, llave):
    res = []
    if os.path.isfile(filename):
        f = open(filename, "r")
        lines = f.readlines()
        f.close()
        for l in lines:
            aux = l.split(",")
            temp = {
                        "var": aux[0].strip(),
                        "encoded": aux[1].strip(),
                        "decoded": decode(aux[1].strip(), llave)
                        }
            res.append(temp)
            print(temp["var"] + "=" + temp["decoded"])
    return res

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='Decoder para cifrado custom de URSA',
                    description='Este decodifica con doble llave',
                    epilog='Ojala que sirva')
    parser.add_argument("-t", "--texto", type=str, required=False)
    parser.add_argument("-f", "--file", type=str, required=False)
    parser.add_argument("-l", "--llave", type=int, required=True, default=99)
    args = parser.parse_args()
   
    if args.texto is not None:
        res = decode(args.texto, args.llave)
        print(res)
    elif args.file is not None:
        res = decode_file(args.file, args.llave)
