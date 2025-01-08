import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

LISTENER_IP = '0.0.0.0'
LISTENING_PORT = 2000
SERVER_PASSWORD = "password"

# RSA key pair for server
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()
server_public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Room management
rooms = {}  # Key: room name, Value: list of connections
user_rooms = {}  # Key: connection, Value: room name
user_keys = {}   # Key: connection, Value: client's public key (for E2EE)

# Start server
def startServer():
    socketInstance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socketInstance.bind((LISTENER_IP, LISTENING_PORT))
    socketInstance.listen(5)
    print("Server started.")

    while True:
        conn, addr = socketInstance.accept()
        threading.Thread(target=handleClient, args=(conn,)).start()

# Handle individual client
def handleClient(conn):
    try:
        # Send server's public key
        conn.sendall(server_public_key_pem)

        # Receive client's public key
        client_public_key_pem = conn.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
        user_keys[conn] = client_public_key

        # Receive and decrypt credentials
        encrypted_credentials = conn.recv(2048)
        credentials = server_private_key.decrypt(
            encrypted_credentials,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        username, password, received_server_password = credentials.split(":")
        if received_server_password != SERVER_PASSWORD:
            conn.sendall(encrypt_message("Invalid server password", client_public_key))
            conn.close()
            return

        conn.sendall(encrypt_message("Login Successful", client_public_key))
        print(f"User {username} authenticated.")

        while True:
            # Receive and decrypt messages
            encrypted_message = conn.recv(2048)
            message = decrypt_message(encrypted_message, server_private_key)

            if message.startswith("/create "):
                room_name = message.split(" ", 1)[1]
                if room_name not in rooms:
                    create_room(conn, room_name)
                else:
                    join_room(conn, room_name)
            else:
                room_name = user_rooms.get(conn)
                if room_name:
                    broadcast(message, conn, room_name)
                else:
                    conn.sendall(encrypt_message("You are not in a room. Use /create or /join to enter a room.", client_public_key))
    except Exception as e:
        print(f"Error: {e}")
        leave_room(conn)

# Encrypt message
def encrypt_message(message, public_key):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt message
def decrypt_message(encrypted_message, private_key):
    return private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

# Room management functions
def create_room(conn, room_name):
    if room_name in rooms:
        conn.sendall(encrypt_message(f"Room {room_name} already exists.", user_keys[conn]))
    else:
        rooms[room_name] = [conn]
        user_rooms[conn] = room_name
        conn.sendall(encrypt_message(f"Room {room_name} created and joined.", user_keys[conn]))

def join_room(conn, room_name):
    if room_name not in rooms:
        conn.sendall(encrypt_message(f"Room {room_name} does not exist.", user_keys[conn]))
    else:
        leave_room(conn)  # Leave current room if in one
        rooms[room_name].append(conn)
        user_rooms[conn] = room_name

def leave_room(conn):
    room_name = user_rooms.pop(conn, None)
    if room_name and room_name in rooms:
        rooms[room_name].remove(conn)
        if not rooms[room_name]:
            del rooms[room_name]

def broadcast(message, sender_conn, room_name):
    for conn in rooms.get(room_name, []):
        if conn != sender_conn:
            try:
                conn.sendall(encrypt_message(message, user_keys[conn]))
            except Exception as e:
                print(f"Broadcast error: {e}")
                leave_room(conn)

if __name__ == "__main__":
    startServer()
