num = [172, 254, 227, 97]

result = [0xe0, 0xcd, 0xab, 0x22, 0xf8, 0xb8, 0x98, 0x0b ,0xd9,0x8d ,0x97 ,0x3e ,0xdf, 0x97, 0x84, 0x0f, 0xf3, 0x97, 0x8d, 0x1c ,0xac,0x0a]

i = 0
for c in result:
    print(chr(c ^ num[i % 4]), end="")
    i += 1