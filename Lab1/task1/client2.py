import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 55555)
client_socket.connect(server_address)

while True:
    text = input("Enter the text to send to the server or enter 'exit': ")
    client_socket.send(text.encode())
    if text.lower() == 'exit':
        break
    response = client_socket.recv(1024)
    print("Received from server:", response.decode())

client_socket.close()