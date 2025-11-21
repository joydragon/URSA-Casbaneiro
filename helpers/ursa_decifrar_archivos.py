#!/usr/bin/python
import io, os, sys

def escribir(b, filename):
    w = open(filename,"ab")
    w.write(b)
    w.close()

def decifrar(filename):
    with open(filename, "rb") as f:
        size = os.path.getsize(filename)
        print("Decifrando " + filename)
        out_filename = filename + ".out"
        first = int.from_bytes(f.read(1), byteorder='big')
        iterador = 0
        res = b''

        for i in range(size):
            c = f.read(1)
            c = int.from_bytes(c, byteorder='big') - int(first+iterador)
            if c < 0:
                c+=256

            res += c.to_bytes(length = 1, byteorder='big')
            iterador = (iterador+1)%10
            if(len(res) > 100000):
                escribir(res, out_filename)
                res = b''

        escribir(res, out_filename)
    return out_filename

if __name__ == "__main__":
    print(sys.argv[1])
    decifrar(sys.argv[1])
