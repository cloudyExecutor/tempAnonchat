import socket
import threading
import sys
import time
from openai import OpenAI

# Point to the local server
client = OpenAI(base_url="http://localhost:7997/v1", api_key="lm-studio")

clients = {}
nicknames = []
banned_ips = set()

def handle_client(client_socket, client_address):
    if client_address[0] in banned_ips:
        client_socket.send("Du bist gebannt.".encode('utf-8'))
        client_socket.close()
        return

    credentials = client_socket.recv(1024).decode('utf-8')
    username, password, register = credentials.split(":")
    if register == "True":
        register_new_user(username, password)
    elif not check_credentials(username, password):
        client_socket.send("Falsche Anmeldeinformationen.".encode('utf-8'))
        client_socket.close()
        return

    clients[client_socket] = username
    nicknames.append(username)
    broadcast_member_list()
    welcome_message = f"{username} hat den Chat betreten."
    broadcast(welcome_message.encode('utf-8'), client_socket)

    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break
            if message.startswith(b"NICK_CHANGE:"):
                old_username, new_username = message.decode('utf-8')[12:].split(':')
                clients[client_socket] = new_username
                nicknames.remove(old_username)
                nicknames.append(new_username)
                broadcast_member_list()
                broadcast(f"{old_username} hat seinen Nickname zu {new_username} geändert.".encode('utf-8'), client_socket)
            elif message.startswith(b"IMAGE:"):
                broadcast(message, client_socket)
            else:
                broadcast(message, client_socket)
                with open('MESSAGES.TXT', 'a') as file:
                    file.write(f"<{username}>[{client_address[0]}]: {message.decode('utf-8')}\n")
        except ConnectionResetError:
            break

    client_socket.close()
    username = clients.pop(client_socket, None)
    if username:
        nicknames.remove(username)
        broadcast_member_list()
        disconnect_message = f"{username} hat den Chat verlassen."
        broadcast(disconnect_message.encode('utf-8'), None)

def broadcast(message, source_socket):
    for client in clients.keys():
        if client != source_socket:
            try:
                client.send(message)
            except:
                client.close()
                clients.pop(client, None)

def broadcast_member_list():
    member_list_str = ",".join(nicknames)
    broadcast(f"MEMBER_UPDATE:{member_list_str}".encode('utf-8'), None)

def check_credentials(username, password):
    with open("cred.txt", "r") as file:
        for line in file:
            stored_username, stored_password = line.strip().split(":")
            if stored_username == username and stored_password == password:
                return True
    return False

def register_new_user(username, password):
    with open("cred.txt", "a") as file:
        file.write(f"{username}:{password}\n")

def load_banned_ips():
    try:
        with open("banland.txt", "r") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        return set()

def save_banned_ips():
    with open("banland.txt", "w") as file:
        for ip in banned_ips:
            file.write(f"{ip}\n")

def broadcast_warning(message):
    broadcast(f"WARNING: {message}".encode('utf-8'), None)

def start_server():
    global banned_ips
    banned_ips = load_banned_ips()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(5)
    print("Server gestartet und wartet auf Verbindungen...")

    def server_console():
        global client
        while True:
            command = input()
            if command.startswith("/ip"):
                print(f"Server IP: {socket.gethostbyname(socket.gethostname())}")
            elif command.startswith("/shutdown"):
                try:
                    delay = int(command.split()[1])
                    warning_message = f"Server wird in {delay} Sekunden heruntergefahren!"
                    print(warning_message)
                    broadcast_warning(warning_message)
                    time.sleep(delay)
                    break
                except (IndexError, ValueError):
                    print("Bitte eine gültige Zeit angeben.")
            elif command.startswith("/report"):
                with open('MESSAGES.TXT', 'r') as file:
                    message_log_str = file.read()
                completion = client.chat.completions.create(
                    model="LM Studio Community/Meta-Llama-3-8B-Instruct-GGUF",
                    messages=[
                        {"role": "system", "content": "You are an inbound ai to a chatapp called AnonChat. its written in python. You have the ability to see the log. if you see bad words you can kick people by just typing in /kick IPADRESS. note that you are just saying /kick <ip adress>. if you are asked to do somthing, do that. note. if you detect violating rules, rate them. are they offensive? or is it okay in the sytaxt? like if someone explains something without offending anyone, its ok, do not kick him then. do not explain. just type /kick <ip adress>. no descriptions. your answer is /kick < ip adress > or /Servermsg No offensive language detected."},
                        {"role": "user", "content": message_log_str}
                    ],
                    temperature=0.7,
                )
                ai_response = completion.choices[0].message.content
                print(ai_response)
                if ai_response == "/ip":
                    print(f"Server IP: {socket.gethostbyname(socket.gethostname())}")
                elif ai_response.startswith("/kick"):
                    ip_to_kick = ai_response.split()[1]
                    kicked = False
                    for client in list(clients.keys()):
                        if client.getpeername()[0] == ip_to_kick:
                            client.send("Du wurdest gekickt.".encode('utf-8'))
                            client.close()
                            clients.pop(client, None)
                            kicked = True
                            break
                    if kicked:
                        broadcast_warning(f"{ip_to_kick} wurde gekickt.")
                    else:
                        print(f"Keine Verbindung mit IP {ip_to_kick} gefunden.")
                elif ai_response.startswith("/ban"):
                    ip_to_ban = ai_response.split()[1]
                    banned_ips.add(ip_to_ban)
                    save_banned_ips()
                    broadcast_warning(f"IP {ip_to_ban} wurde gebannt.")
            else:
                print("Unbekannter Befehl.")

    threading.Thread(target=server_console, daemon=True).start()

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Verbindung von {client_address} akzeptiert!")
        threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    start_server()
