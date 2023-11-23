import socket
import time
import threading


def client(client_socket, client_address):
    while True:
        data = client_socket.recv(1024)

        if data.lower().decode() == 'exit':
            break

        time.sleep(5)

        if data.strip():
            print(f"Received from client {client_address}: {data.decode()}")
            response = "The data was obtained by " + time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            print("Error: No data received.")
            response = "Error: No data received."
        client_socket.send(response.encode())

    client_socket.close()


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('127.0.0.1', 55555)
server_socket.bind(server_address)

server_socket.listen(5)
print("The server is ready to listen for connections...")

while True:
    client_socket, client_address = server_socket.accept()
    print("The connection is established:", client_address)
    client_handler = threading.Thread(target=client, args=(client_socket, client_address))
    client_handler.start()

client_socket.close()
server_socket.close()
