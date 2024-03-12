from tkinter import Tk, Label, Entry, Button, Text  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives import padding  
import binascii
import base64  
import socket  
  
# Generate encryption key from the shared password  
def generate_key_from_password(password):  
    salt = b'some_random_salt'  # You can generate a random salt  
    kdf = PBKDF2HMAC(  
        algorithm=hashes.SHA256(),  
        length=32,  # AES-256 key length  
        salt=salt,  
        iterations=100000  # Choose an appropriate iteration count  
    )  
    key = kdf.derive(password.encode())  
    return key  
  
# Encrypt message using the generated key  
def encrypt_message(message, key):  
    iv = b'some_random_iv16'  # You can generate a random initialization vector  

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  
    encryptor = cipher.encryptor()  
  
    padder = padding.PKCS7(algorithms.AES.block_size).padder()  
    padded_message = padder.update(message.encode()) + padder.finalize()  
  
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()  
    return ciphertext  
  
# Decrypt ciphertext using the generated key  
def decrypt_message(ciphertext, key):  
    iv = b'some_random_iv16'  # You need to use the same initialization vector used for encryption 

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())  
    decryptor = cipher.decryptor()  
  
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()  
  
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()  
    plaintext = unpadder.update(padded_message) + unpadder.finalize()  
    return plaintext.decode()  
  
# GUI functions  
def send_message():  
    message = input_text.get()  
    ciphertext = encrypt_message(message, shared_key)  
    sent_text.insert('end', binascii.hexlify(ciphertext).decode() + '\n')  
    client_socket.sendall(ciphertext)  
    
def receive_message():  
    ciphertext = client_socket.recv(1024)
    if ciphertext:
        plaintext = decrypt_message(ciphertext, shared_key)
        received_text.insert('end', "Received: " + plaintext + '\n')
    else:
        print("Connection closed by server.")
        client_socket.close()
        window.quit()


  # Key management functions  
    
def set_up_key():
    global shared_key
    password = password_entry.get()
    shared_key = generate_key_from_password(password)
    

def update_shared_key():  
    global shared_key  
    password = password_entry.get()  
    shared_key = generate_key_from_password(password)  
    
# Initialize the shared key  
shared_key = None  
  
# Create the GUI window  
window = Tk()  
window.title("Secure Messaging Tool")  
  
# Label and input field for the shared password  
password_label = Label(window, text="Shared Password:")  
password_label.pack()  
password_entry = Entry(window, show="*")  
password_entry.pack()  
  
# Button to set up the shared key  
setup_button = Button(window, text="Set Up", command=lambda: set_up_key())  
setup_button.pack()  
  
# Label and input field for input message  
input_label = Label(window, text="Input Message:")  
input_label.pack()  
input_text = Entry(window)  
input_text.pack()  
  
# Button to send the message  
send_button = Button(window, text="Send", command=lambda: send_message())  
send_button.pack()  
  
# Text widget to display sent ciphertext  
sent_text = Text(window)  
sent_text.pack()  
  
# Label and text widget for received ciphertext and plaintext  
received_label = Label(window, text="Received Message:")  
received_label.pack()  
received_text = Text(window)  
received_text.pack()  
  
  
# Button to decrypt and display the received message  
decrypt_button = Button(window, text="Decrypt", command=lambda: receive_message())  
decrypt_button.pack()  
    
# Initialize the client socket  
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
server_address = ('127.0.0.1', 12345)  # Replace with the server address and port  
client_socket.connect(server_address)  
# Start the GUI event loop  
window.mainloop()  
  
# Close the client socket  
client_socket.close()  