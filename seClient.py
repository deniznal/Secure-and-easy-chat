import socket
import threading
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPalette, QColor
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Global variables
SERVER_ADDRESS = '16.171.165.2'  # Server IP
SERVER_PORT = 2000

# Generate client's RSA key pair
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
client_public_key = client_private_key.public_key()
client_public_key_pem = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Client socket setup
socketInstance = socket.socket()
socketInstance.connect((SERVER_ADDRESS, SERVER_PORT))

# Receive server's public key
server_public_key_pem = socketInstance.recv(2048)
server_public_key = serialization.load_pem_public_key(server_public_key_pem)

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

class LoginWindow(QWidget):
    loginSuccess = pyqtSignal()
    loginFailed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Easy Chat")
        self.setStyleSheet("background-color: #FFE4E1;")  # Soft pink background
        self.setupUI()

    def setupUI(self):
        self.welcomeLabel = QLabel("Login to Secure and Easy Chat", self)
        self.welcomeLabel.setStyleSheet("font-size: 24px; color: #FF69B4;")  # Hot pink text

        self.serverPasswordLineEdit = QLineEdit(self)
        self.serverPasswordLineEdit.setEchoMode(QLineEdit.Password)
        self.serverPasswordLineEdit.setPlaceholderText("Server Password: ")
        self.serverPasswordLineEdit.setStyleSheet("background-color: #FFB6C1; color: #800080; border-radius: 10px;")  # Light pink input

        self.usernameLineEdit = QLineEdit(self)
        self.usernameLineEdit.setPlaceholderText("Username: ")
        self.usernameLineEdit.setStyleSheet("background-color: #FFB6C1; color: #800080; border-radius: 10px;")

        self.passwordLineEdit = QLineEdit(self)
        self.passwordLineEdit.setEchoMode(QLineEdit.Password)
        self.passwordLineEdit.setPlaceholderText("Password: ")
        self.passwordLineEdit.setStyleSheet("background-color: #FFB6C1; color: #800080; border-radius: 10px;")

        self.loginButton = QPushButton("Login", self)
        self.loginButton.setStyleSheet("background-color: #FF69B4; color: white; border-radius: 10px; padding: 5px; font-weight: bold;")

        layout = QVBoxLayout(self)
        layout.addWidget(self.welcomeLabel)
        layout.addWidget(self.serverPasswordLineEdit)
        layout.addWidget(self.usernameLineEdit)
        layout.addWidget(self.passwordLineEdit)
        layout.addWidget(self.loginButton)

        self.loginButton.clicked.connect(self.startLoginThread)
        self.loginSuccess.connect(self.onLoginSuccess)
        self.loginFailed.connect(self.onLoginFailed)

    def startLoginThread(self):
        threading.Thread(target=self.login).start()

    def login(self):
        try:
            server_password = self.serverPasswordLineEdit.text()
            username = self.usernameLineEdit.text()
            global clientName
            clientName = self.usernameLineEdit.text()
            password = self.passwordLineEdit.text()

            # Encrypt credentials
            credentials = f"{username}:{password}:{server_password}".encode()
            encrypted_credentials = encrypt_message(credentials.decode(), server_public_key)

            # Send credentials and public key
            socketInstance.sendall(client_public_key_pem)
            socketInstance.sendall(encrypted_credentials)

            # Wait for server's response
            encrypted_response = socketInstance.recv(2048)
            response = decrypt_message(encrypted_response, client_private_key)

            if response == "Login Successful":
                self.loginSuccess.emit()
            else:
                self.loginFailed.emit(response)
        except Exception as e:
            self.loginFailed.emit(f"Error: {str(e)}")

    def onLoginSuccess(self):
        self.close()
        chat_window = ChatWindow()
        chat_window.show()

    def onLoginFailed(self, error_message):
        QMessageBox.critical(self, "Login Failed", error_message)

class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure and Easy Chat")
        self.setStyleSheet("background-color: #FFF0F5;")  # Lavender Blush background
        self.currentRoom = None
        self.joinedRooms = []  # List to store previously joined rooms
        self.RoomHistory = {}  # List to store room history
        self.setupUI()

    def setupUI(self):
        # Room Management UI
        self.roomInput = QLineEdit(self)
        self.roomInput.setPlaceholderText("Enter room name to create/join")
        self.roomInput.setStyleSheet("background-color: #FFB6C1; color: #800080; border-radius: 10px;")

        self.roomButton = QPushButton("Create/Join Room", self)
        self.roomButton.setStyleSheet("background-color: #FF69B4; color: white; border-radius: 10px; font-weight: bold;")

        self.roomList = QComboBox(self)
        self.roomList.setStyleSheet("background-color: #FFB6C1; color: #800080; border-radius: 10px;")
        self.roomList.addItem("Select a previously joined room")  # Default option

        # Chat UI
        self.textEdit = QTextEdit(self)
        self.textEdit.setReadOnly(True)
        self.textEdit.setStyleSheet("background-color: #FFF0F5; color: #800080; border-radius: 10px;")

        self.lineEdit = QLineEdit(self)
        self.lineEdit.setStyleSheet("background-color: #FFB6C1; color: #800080; border-radius: 10px;")

        self.sendButton = QPushButton("Send", self)
        self.sendButton.setStyleSheet("background-color: #FF69B4; color: white; border-radius: 10px; font-weight: bold;")

        # Layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.roomInput)
        layout.addWidget(self.roomButton)
        layout.addWidget(self.roomList)
        layout.addWidget(self.textEdit)
        h_layout = QHBoxLayout()
        h_layout.addWidget(self.lineEdit)
        h_layout.addWidget(self.sendButton)
        layout.addLayout(h_layout)

        self.setLayout(layout)

        # Event Listeners
        self.roomButton.clicked.connect(self.handleRoomInput)
        self.roomList.currentIndexChanged.connect(self.handleRoomList)
        self.sendButton.clicked.connect(self.sendMessage)
        threading.Thread(target=self.receiveMessages).start()

    def handleRoomInput(self):
        room_name = self.roomInput.text().strip()
        if room_name:
            self.joinRoom(room_name)

    def handleRoomList(self):
        selected_room = self.roomList.currentText()
        if selected_room != "Select a previously joined room":
            self.joinRoom(selected_room)

    def joinRoom(self, room_name):
        self.currentRoom = room_name

        if room_name not in self.joinedRooms:
            self.RoomHistory[room_name] = ""
            self.joinedRooms.append(room_name)
            self.roomList.addItem(room_name)
            self.textEdit.clear()
            self.textEdit.append(f"{clientName} joined room: {room_name}")
        else:
            self.textEdit.setText(self.RoomHistory[room_name])

        self.RoomHistory[room_name] = self.textEdit.toPlainText()

        command = f"/create {room_name}"
        socketInstance.sendall(encrypt_message(command, server_public_key))
        command2 = f"{clientName} joined room: {room_name}"
        socketInstance.sendall(encrypt_message(command2, server_public_key))

    def sendMessage(self):
        if not self.currentRoom:
            self.textEdit.append("Please create or join a room first.")
            return

        message = self.lineEdit.text().strip()
        newmessage = f"{clientName}: {message}"
        if message:
            socketInstance.sendall(encrypt_message(newmessage, server_public_key))
            self.textEdit.append(f"{newmessage}")
            self.lineEdit.clear()
            self.RoomHistory[self.currentRoom] = self.textEdit.toPlainText()

    def receiveMessages(self):
        while True:
            try:
                encrypted_message = socketInstance.recv(2048)
                message = decrypt_message(encrypted_message, client_private_key)
                self.textEdit.append(message)
                self.RoomHistory[self.currentRoom] = self.textEdit.toPlainText()
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())
