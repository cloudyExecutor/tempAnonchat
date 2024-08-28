import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox, filedialog
from PIL import Image, ImageTk
import base64
import io

class ChatClient:
    def __init__(self, server_ip, username, password, register):
        self.server_ip = server_ip
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.server_ip, 12345))

        self.root = tk.Tk()
        self.root.title("AnonChat")

        # Hauptfenster für Chat und Mitgliederliste
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=10, pady=10)

        # Chat Frame
        self.chat_frame = tk.Frame(self.main_frame)
        self.chat_frame.grid(row=0, column=0, padx=10, pady=10)

        self.chat_text = scrolledtext.ScrolledText(self.chat_frame, state=tk.DISABLED, width=50, height=20)
        self.chat_text.pack(padx=5, pady=5)

        # Mitglieder Frame
        self.members_frame = tk.Frame(self.main_frame)
        self.members_frame.grid(row=0, column=1, padx=10, pady=10)

        self.members_label = tk.Label(self.members_frame, text="Mitglieder")
        self.members_label.pack()

        self.members_listbox = tk.Listbox(self.members_frame, height=20)
        self.members_listbox.pack()

        # Eingabe Frame
        self.entry_frame = tk.Frame(self.root)
        self.entry_frame.pack(padx=10, pady=10)

        self.entry_text = tk.Entry(self.entry_frame, width=40)
        self.entry_text.pack(side=tk.LEFT, padx=5)
        self.entry_text.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.entry_frame, text="Senden", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        # Change Nickname Button
        self.change_nickname_button = tk.Button(self.root, text="Change Nickname", command=self.change_nickname)
        self.change_nickname_button.pack()

        # Send Image Button
        self.send_image_button = tk.Button(self.root, text="Bild senden", command=self.send_image)
        self.send_image_button.pack()

        self.client_socket.send(f"{username}:{password}:{register}".encode('utf-8'))

        threading.Thread(target=self.receive_messages, daemon=True).start()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                if message.startswith("MEMBER_UPDATE:"):
                    self.update_member_list(message[14:])
                elif message.startswith("IMAGE:"):
                    self.display_image(message[6:])
                else:
                    self.display_message(message)
            except ConnectionResetError:
                break
        self.client_socket.close()

    def update_member_list(self, member_list_str):
        members = member_list_str.split(',')
        self.members_listbox.delete(0, tk.END)
        for member in members:
            self.members_listbox.insert(tk.END, member)

    def display_message(self, message):
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, message + "\n")
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.yview(tk.END)

    def send_message(self, event=None):
        message = self.entry_text.get()
        if message:
            formatted_message = f"{self.username}: {message}"
            self.client_socket.send(formatted_message.encode('utf-8'))
            self.display_message(formatted_message)  # Zeigt gesendete Nachricht im Chat-Fenster an
            self.entry_text.delete(0, tk.END)

    def send_image(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, "rb") as file:
                encoded_image = base64.b64encode(file.read()).decode('utf-8')
                image_message = f"IMAGE:{encoded_image}"
                self.client_socket.send(image_message.encode('utf-8'))

    def display_image(self, encoded_image):
        decoded_image = base64.b64decode(encoded_image)
        image_data = io.BytesIO(decoded_image)
        pil_image = Image.open(image_data)
        tk_image = ImageTk.PhotoImage(pil_image)
        
        image_label = tk.Label(self.chat_frame, image=tk_image)
        image_label.image = tk_image
        self.chat_text.window_create(tk.END, window=image_label)
        self.chat_text.insert(tk.END, "\n")
        self.chat_text.yview(tk.END)

    def change_nickname(self):
        new_username = simpledialog.askstring("Username ändern", "Neuen Username eingeben:", parent=self.root)
        if new_username:
            self.client_socket.send(f"NICK_CHANGE:{self.username}:{new_username}".encode('utf-8'))
            self.username = new_username

    def on_closing(self):
        self.client_socket.send(f"{self.username} hat den Chat verlassen.".encode('utf-8'))
        self.client_socket.close()
        self.root.quit()

def server_selection():
    root = tk.Tk()
    root.withdraw()  # Versteckt das Hauptfenster vorübergehend
    
    def start_chat_client(server_ip, username, password, register):
        if server_ip and username and password:
            ChatClient(server_ip, username, password, register)

    def show_server_selection():
        selection_window = tk.Toplevel(root)
        selection_window.title("Server Auswahl")

        tk.Label(selection_window, text="Wähle einen Server aus:").pack(padx=10, pady=10)

        def select_server(ip):
            username = simpledialog.askstring("Username", "Gib deinen Username ein:", parent=selection_window)
            password = simpledialog.askstring("Passwort", "Gib dein Passwort ein:", show="*", parent=selection_window)
            register = simpledialog.askstring("Registrieren", "Möchtest du dich registrieren? (True/False):", parent=selection_window)
            if username and password and register:
                start_chat_client(ip, username, password, register)
                selection_window.destroy()

        servers = [
            ("Server #0001", "192.168.2.182"),
            ("Server #0002", "192.168.2.183")
        ]

        for name, ip in servers:
            tk.Button(selection_window, text=name, command=lambda ip=ip: select_server(ip)).pack(padx=5, pady=5)

        tk.Button(selection_window, text="Benutzerdefiniert", command=lambda: custom_server_input()).pack(padx=10, pady=10)

    def custom_server_input():
        ip = simpledialog.askstring("Benutzerdefinierter Server", "Gib die IP-Adresse des Servers ein:")
        username = simpledialog.askstring("Username", "Gib deinen Username ein:")
        password = simpledialog.askstring("Passwort", "Gib dein Passwort ein:", show="*")
        register = simpledialog.askstring("Registrieren", "Möchtest du dich registrieren? (True/False):")
        if ip and username and password and register:
            start_chat_client(ip, username, password, register)

    show_server_selection()
    root.mainloop()

if __name__ == "__main__":
    server_selection()
