# Secure-and-easy-chat
A simple application that lets users communicate in multiple group chats with symmetrical RSA encryption.

## Features
* Supports user authentication
* Multiple groupchats
* Symmetrical encryption
* Local chat history
* Connects to a AWS server

## Security concerns
* As messages are symmetrically encrypted, server is decrypting users' messages. The contents of what the user is sending should be taken into consideration by the user accordingly.

## How to use
* Edit the server's port number and IP address accordingly on the client and server. Simply run the client and server with python and input the server password alongside your own credentials.
