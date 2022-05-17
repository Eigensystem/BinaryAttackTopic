from Crypto.Util.number import *
from secret import flag

import gmpy2

def gen():
    p = getStrongPrime(1024)
    q = getStrongPrime(1024)
    n = p * q
    e = getPrime(500)
    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    return (d, e, n)

def enc(plaintext, e, n):
    m = bytes_to_long(plaintext)
    return pow(m, e, n)

e, d, n = gen()
c = enc(flag, e, n)
with open("cipher.txt", "w") as f:
    f.write("e = " + str(e) + "\n")
    f.write("n = " + str(n) + "\n")
    f.write("c = " + str(c) + "\n")