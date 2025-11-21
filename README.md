# URSA-Casbaneiro
Algunos scripts que pueden usarse para revisar archivos/links de URSA y/o Casbaneiro

La idea de estos scripts es que puedan ser usados directamente con un link o con un archivo "cid" o de los "gX". Todavía no está correctamente implementado el descomprimir y la lectura de los archivos .zip y/o .hta.

# SETUP

1) Inicializacion de ambiente virtual (python3-venv)

```
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
```

2) Instalacion de requerimientos extra (con npm)

```
sudo npm install --global deobfuscator # Puede no ser con sudo
```

# Uso de la herramienta

### Obtener IOCs (ursa_obtener_iocs.py)

Para usar la herramienta basta con ejecutarla desde la línea de código con el parámetro correcto:

```
Aplicacion para descargar los archivos y mostrar las URL de URSA y Casbaneiro"

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     La URL para la descarga del archivo inicial.
  -f FILENAME, --filename FILENAME
                        El archivo a analizar para la revision.
  -g, --g-file          Flag para dar a conocer que el archivo es uno de tipo gX (Mispadu).
  -c, --cid-file        Flag para dar a conocer que el archivo es uno de tipo cid (Casbaneiro).


Ejemplos:

$ ursa_obtener_iocs.py -u https://dominio.example.com/cid

o

$ ursa_obtener_iocs.py -c -f ./g1
``` 

Con esto la herramienta *crea una carpeta "temp"* en la ruta local para almarcenar todos los archivos descargados y procesados.
