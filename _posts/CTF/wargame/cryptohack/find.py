enc_flag = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

flag = ""
secretKey = b"myXORkey"

for i, v in enumerate(enc_flag):
    flag += chr(v ^ secretKey[i % 8])

print(flag)