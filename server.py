import socket
import threading

# Define the server address and port
SERVER_ADDRESS = ('127.0.0.1', 12345)

# Function to handle each client connection
def handle_client(client_socket, client_address):
    print(f"Connection from {client_address} has been established.")

    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        # Broadcast the received message to all connected clients
        broadcast_message(data, client_socket)

    print(f"Connection from {client_address} has been closed.")
    client_socket.close()

# Function to broadcast a message to all connected clients except the sender
def broadcast_message(message, sender_socket):
    for client_socket in client_sockets:
        if client_socket != sender_socket:
            client_socket.sendall(message)

# Initialize the server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(SERVER_ADDRESS)
server_socket.listen(5)  # Listen for incoming connections

print("Server is running and listening for connections...")

client_sockets = []

# Main server loop
while True:
    client_socket, client_address = server_socket.accept()
    client_sockets.append(client_socket)

    # Start a new thread to handle the client connection
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()
