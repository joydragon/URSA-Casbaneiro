#!/usr/bin/env python3

import sys, os
import shutil, re
import requests
import argparse, hashlib

from autoit_ripper import extract, AutoItVersion

from zipfile import ZipFile
import helpers.lznt1
import helpers.ursa_decode_strings as ursa_decode_strings
import helpers.ursa_decifrar_archivos as ursa_decifrar_archivos

algos = ["md5","sha1","sha256","sha512"]

def init():
    out_dir = "./temp/"
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    s = requests.Session()

    headers = {
        'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)',
        'Language': 'AcAccept-Language: es-CL, es;q=0.9, en-US;q=0.8, en;q=0.7'
    }

    s.headers = headers
    s.allow_redirects = False


    config = {
        "out_dir" : out_dir,
        "session" : s
    }
    return config

def get_file_hash(filename, algorithm):
    hash_func = hashlib.new(algorithm)
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):  # Read in 4KB chunks
            hash_func.update(chunk)
    return hash_func.hexdigest()

def get_main_file_hashes(filename):
    res = {}
    for algo in algos:
        try:
            file_hash = get_file_hash(filename, algo)
            res[algo] = file_hash
        except ValueError:
            pass
    return res

def get_filename(res):
    if not isinstance(res, str) and "Content-Disposition" in res.headers:
        fname = re.findall('filename=(.+)', res.headers["Content-Disposition"])
        if fname is not None and len(fname) > 0:
            return fname[0]
    elif not isinstance(res, str):
        url = res.url
    else:
        url = res
    temp = url.split("?")[0].split('/')
    if len(temp) <= 3:
        return url.replace('/',"_").replace(":","")
    while temp[-1] == '':
        del temp[-1]
    return temp[-1]

def buscar_url(texto):
    res = re.search(r'.*(https://[0-9.]+\.host\.secureserver\.net/[^(\'|")]+)', texto)
    if res is not None:
        return res.group(1)
    return None

def limpiar_concatenaciones_texto(texto):
    res = re.sub(r'"\s*\+\s*"','',texto)
    return res

def descargar_archivo(url, s, out_dir = "./temp/"):
    print("Descargando de: " + url)
    res = s.get(url)
    if res.status_code != 200:
        raise Exception("ERROR " + res.status_code + ": Para obtener informacion.")

    temp_file = get_filename(res)
    temp_file = os.path.abspath(os.path.join(".",out_dir, temp_file))

    with open(temp_file, 'wb') as fd:
        for chunk in res.iter_content(chunk_size=512):
            fd.write(chunk)
    
    print("Archivo escrito: " + temp_file)
    return temp_file 

def obtener_urls_casbaneiro(texto):
    if shutil.which("synchrony") is None:
        raise RuntimeError("ERROR: No se encuentra el binario de synchrony, lo instaste?")
    res = re.search(r'<!\[CDATA\[(.*)\]\]', texto, re.DOTALL)
    if res is not None:
        temp_js = "./temp/temp_js.js"
        clean_js = "./temp/temp_js.cleaned.js"
        f = open(temp_js, "w")
        f.write(res.group(1))
        f.close()
        os.system("synchrony deobfuscate -o '" + clean_js + "' '" + temp_js + "'")
        if os.path.isfile(clean_js):
            f = open(clean_js)
            texto = f.read()
            f.close()
            res = re.findall("'(https:[^']+)'", texto)
            if res is not None:
                return res
            return None
        else:
            raise Exception("ERROR: Hubo un error en el deobfuscado de: " + temp_js)
        print("Listo?")
    return res

def extraer_dll_au3(filename):
    with open(filename, "r") as f:
        file_content = f.readlines()

    res = b''
    for l in file_content:
        m = re.search(r'DLLBINARY\s+&=\s+"(0x)?([A-Fa-f0-9]+)"',l)
        if m is not None:
            res += bytes.fromhex(m.group(2))

    out_file = filename + "_out.dll"
    with open(out_file, "wb") as f:
        f.write(res)

    return out_file

def decifrar_autoit(filename):
    with open(filename, "rb") as f:
        file_content = f.read()
    content_list = extract(data=file_content)

    out_file = filename + ".au3"
    with open(out_file, "wb") as f:
        f.write(content_list[0][1])
    return out_file

def obtener_archivos_finales(urls, out_dir = "."):
    file1 = os.path.join(out_dir, get_filename(urls[0]))
    file2 = os.path.join(out_dir, get_filename(urls[1]))
    file3 = os.path.join(out_dir, get_filename(urls[2]))

    with ZipFile(file1, "r") as zObj:
        file1out = os.path.join(out_dir, zObj.infolist()[0].filename)
        zObj.extractall(out_dir)
    file1fin = ursa_decifrar_archivos.decifrar(file1out)
    print("* El binario con el malware final es: " + file1fin)

    file2out = ursa_decifrar_archivos.decifrar(file2)
    with ZipFile(file2out, "r") as zObj:
        file2fin = os.path.join(out_dir, zObj.infolist()[0].filename)
        zObj.extractall(out_dir)
        try:
            file2au3 = decifrar_autoit(file2fin)
            file2dll = extraer_dll_au3(file2au3)
        except Exception as e:
            print("ERROR: " + str(e))
    print("* El archivo con el script de AutoIt compilado es: " + file2fin)
    print("* El archivo con el script de AutoIt decifrado es: " + file2au3)
    print("* El archivo con la libreria .dll que carga el malware es: " + file2dll)

    file3out = ursa_decifrar_archivos.decifrar(file3)
    with ZipFile(file3out, "r") as zObj:
        file3fin = os.path.join(out_dir, zObj.infolist()[0].filename)
        zObj.extractall(out_dir)
    print("* El archivo con el binario de AutoIt es: " + file3fin)

    return [file1fin, file2fin, file2dll, file3fin]

def buscar_nombre_decode(codigo):
    res = re.search(r'function\s+(de[a-zA-Z0-9]+_17)\(', codigo)
    if res is not None:
        return res.group(1)
    return res

def buscar_key(codigo):
    res = re.search(r'const\s+([a-zA-Z0-9]+_1)\s+=\s+([0-9]+)', codigo)
    if res is not None:
        return (res.group(1), int(res.group(2)))
    return res

def extraer_variables(texto):
    strings = []
    res = re.search(r'<!\[CDATA\[(.*)\]\]', texto, re.DOTALL)
    if res is not None:
        codigo = res.group(1)
        func = buscar_nombre_decode(codigo)
        (keyname,keyval) = buscar_key(codigo)
        strings = re.findall(r'\s*([a-zA-Z0-9_]+)\s*=\s*' + func + r'\("([^"]+)"\s*,\s*' + keyname + r'\)', codigo)
    return (func, keyname, keyval, strings)

def obtener_urls_de_vars(var_limpias, keyval, session):
    suf_base = "_3"
    suf_base2 = "_3W2"
    suf_ext = "_6"
    suf_mid1 = "_56"
    suf_mid3 = "_58"
    base = {key: val for key, val in var_limpias.items() if re.search(f"{suf_base}$", key) and val.startswith("http")} 
    base = list(base.values())[0]
    ext = {key: val for key, val in var_limpias.items() if re.search(f"{suf_ext}$", key) and val.startswith(".")} 
    ext = list(ext.values())[0]
    mid1 = {key: val for key, val in var_limpias.items() if re.search(f"{suf_mid1}$", key)} 
    mid1 = list(mid1.values())[0]
    mid3 = {key: val for key, val in var_limpias.items() if re.search(f"{suf_mid3}$", key)} 
    mid3 = list(mid3.values())[0]
    url1 = base + mid1 + ext
    url3 = base + mid3 + ext

    base2 = {key: val for key, val in var_limpias.items() if re.search(f"{suf_base2}$", key)} 
    base2 = list(base2.values())[0]
    url_med = base + ".php"
    aux = session.get(url_med)
    temp = ursa_decode_strings.decode(aux.text.strip(), 13)
    mid2 = temp.split("#")[3]
    url2 = base2 + mid2 + ext

    return [url1, url2, url3, url_med]

def procesar_archivo(archivo, is_g_file = False, is_cid_file = False, iocs = []):
    config = init()

    out_dir = config["out_dir"]
    s = config["session"]

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    f = open(archivo, "r")
    texto = f.read()
    f.close()

    if is_g_file:
        (func, keyname, keyval, strings) = extraer_variables(texto)
        var_limpias = {}
        f = open(out_dir + "resultados.txt", "w")
        for st in strings:
            var_limpias[st[0]] = ursa_decode_strings.decode(st[1], keyval)
            f.write(st[0] + " = " + var_limpias[st[0]] + "\n")
        f.close()
        urls = obtener_urls_de_vars(var_limpias = var_limpias, keyval = keyval, session = s)
        iocs += urls
        for u in urls:
            temp_file = descargar_archivo(u, s, out_dir)
            hashes = get_main_file_hashes(temp_file)
            iocs.append({"filename": os.path.basename(temp_file), "hashes": hashes})
        files = obtener_archivos_finales(urls, out_dir)
        for temp_file in files:
            hashes = get_main_file_hashes(temp_file)
            iocs.append({"filename": os.path.basename(temp_file), "hashes": hashes})
        print("Listo!")

    elif is_cid_file:
        urls = obtener_urls_casbaneiro(texto)
        if urls is not None:
            iocs += urls
            for u in urls:
                temp_file = descargar_archivo(u, s, out_dir)
                hashes = get_main_file_hashes(temp_file)
                iocs.append({"filename": os.path.basename(temp_file), "hashes": hashes})
                if temp_file.lower().find("crt") >= 0:
                    print("Se intenta descomprimir el archivo: " + temp_file)
                    lznt_file = lznt1.main(temp_file)
                    hashes = get_main_file_hashes(lznt_file)
                    iocs.append({"filename": os.path.basename(lznt_file), "hashes": hashes})
                    print("* El binario del malware es: " + lznt_file)

    elif not is_cid_file and not is_g_file:
        url = buscar_url(texto)
        iocs.append(url)
        temp_file = descargar_archivo(url, s, out_dir)

        f = open(temp_file, "r")
        texto = f.read()
        f.close()
            
        res = limpiar_concatenaciones_texto(texto)
        g = re.search(r'"script:([^"]+/cid)"', res, re.IGNORECASE)
        if g is not None:
            print("No es URSA, es Casbaneiro.")
            url = g.group(1)
            iocs.append(url)
            temp_file = descargar_archivo(url, s, out_dir)
            main(temp_file, is_cid_file)
        else:
            print("TODO!")

    print("")
    print("-"*50)
    print("IOCS")
    for i in iocs:
        print("- " + str(i) )
    print("Fin?")

def descargar_archivo_inicial(url):
    config = init()
    temp_file = descargar_archivo(url, config["session"], out_dir = config["out_dir"])
    c_file = False
    g_file = False
    if re.search(r'cid/?$', url) is not None:
        c_file = True
    elif re.search(r'g[0-9]+/?', url) is not None:
        g_file = True

    procesar_archivo(archivo = temp_file, is_g_file = g_file, is_cid_file = c_file, iocs = [url])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    description='Aplicacion para descargar los archivos y mostrar las URL de URSA y Casbaneiro"',
                    epilog='Ojala que les sirva')
    parser.add_argument("-u", "--url", type=str, help="La URL para la descarga del archivo inicial.")
    parser.add_argument("-f", "--filename", type=str, help="El archivo a analizar para la revision.")
    parser.add_argument("-g", "--g-file", action="store_true", help="Flag para dar a conocer que el archivo es uno de tipo gX (Mispadu).")
    parser.add_argument("-c", "--cid-file", action="store_true", help="Flag para dar a conocer que el archivo es uno de tipo cid (Casbaneiro).")
    args = parser.parse_args()
    if args.url is None and args.filename is None:
        parser.error("Se necesita una URL (-u) o un archivo (-f) para el análisis.")

    if args.url is not None:
        descargar_archivo_inicial(args.url)
    else:
        res = procesar_archivo(archivo = args.filename, is_g_file = args.g_file, is_cid_file = args.cid_file)
