import socket


s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.bind((2, 52))
s.listen()

while True:
  client, addr = s.accept()
  print(f"{client}, {addr}")
