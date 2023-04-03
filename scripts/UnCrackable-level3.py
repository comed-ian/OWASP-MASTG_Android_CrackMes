ct = [0x1549170f1311081d, 0x15131d5a1903000d, 0x14130817005a0e08]
key = "pizzapizzapizzapizzapizz"
for j in range(3):
    for i in range(8):
        print(chr((ct[j] >> (8 * i) & 0xff) ^ ord(key[i + j * 8])), end="")
print()
