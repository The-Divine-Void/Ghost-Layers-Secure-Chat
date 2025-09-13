import tkinter as tk
from tkinter import ttk, scrolledtext
import socket, threading, base64, secrets, hmac, hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# ----------------- Glyph Branding Layer -----------------
glyph_map = {
    **dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", list("дБⲊϕ𞤒ҐⰔߒYუꓘՀကЛΣφՋণডႥဂλЖ㐅ψℵ"))),
    **dict(zip("abcdefghijklmnopqrstuvwxyz", list("𐒀𑀩€𐑓ᛂ𐰯𐒍ᚺπ𐌾𐑗ᛚ𐎈∆ᜂ§𐓀𐰺𐊊𐰕𐎒ᚡ𐑇√𐒎𐤌"))),
    **dict(zip("0123456789", list("0123456789"))),
    "+": "~", # safe for LoRa/TCP
    "/": "*",
    "=": "^"
}
reverse_glyph_map = {v: k for k, v in glyph_map.items()}

def to_glyph_base64(b64_string):
    return ''.join(glyph_map.get(c, '?') for c in b64_string)

def from_glyph_base64(glyph_string):
    return ''.join(reverse_glyph_map.get(c, '?') for c in glyph_string)

# ----------------- Crypto Core (AES-CBC + HMAC) -----------------
BLOCK_SIZE = 16

def encrypt_message(plaintext, key):
    iv = secrets.token_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # PKCS7 Padding
    pad_len = BLOCK_SIZE - len(plaintext.encode()) % BLOCK_SIZE
    padded = plaintext.encode() + bytes([pad_len])*pad_len
    ciphertext = cipher.encrypt(padded)
    # HMAC for integrity
    tag = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(iv + ciphertext + tag).decode()

def decrypt_message(b64_string, key):
    try:
        raw = base64.b64decode(b64_string)
        iv, ciphertext, tag = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:-32], raw[-32:]
        # Verify HMAC
        if not hmac.compare_digest(hmac.new(key, iv+ciphertext, hashlib.sha256).digest(), tag):
            return None
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        pad_len = padded[-1]
        return padded[:-pad_len].decode()
    except:
        return None

# ----------------- Diffie-Hellman -----------------
P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        'E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF', 16)
G = 2

def perform_dh_handshake(sock, is_server=False):
    priv = secrets.randbits(256)
    pub = pow(G, priv, P)
    if is_server:
        client_pub = int(sock.recv(1024).decode())
        sock.send(str(pub).encode())
        shared = pow(client_pub, priv, P)
    else:
        sock.send(str(pub).encode())
        server_pub = int(sock.recv(1024).decode())
        shared = pow(server_pub, priv, P)
    key = PBKDF2(str(shared).encode(), b'ghostlayers', dkLen=32, count=100000)
    return key

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

# ----------------- Ghost Layers Chat GUI -----------------
class GhostLayersChat(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("=== [GHOST-LAYERS] === coded by sacred G")
        self.configure(bg="#000000")
        self.geometry("900x600")
        self.sock = None
        self.aes_key = None
        self.running = True
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', background='#000000', foreground='#39FF14')
        style.configure('TLabel', background='#000000', foreground='#39FF14')
        style.configure('TButton', background='#222222', foreground='#39FF14')
        style.map('TButton', background=[('active', '#333333')])
        style.configure('TEntry', fieldbackground='#111111', foreground='#39FF14')

        ttk.Label(self, text="Peer IP:").pack(padx=5, pady=5, anchor='w')
        self.peer_ip_entry = ttk.Entry(self); self.peer_ip_entry.insert(0, "127.0.0.1")
        self.peer_ip_entry.pack(fill='x', padx=5)

        ttk.Label(self, text="Port:").pack(padx=5, pady=5, anchor='w')
        self.port_entry = ttk.Entry(self); self.port_entry.insert(0, "5150")
        self.port_entry.pack(fill='x', padx=5)

        self.connect_button = ttk.Button(self, text="Connect as Client", command=self.connect_to_peer)
        self.connect_button.pack(fill='x', padx=5, pady=5)

        self.server_button = ttk.Button(self, text="Start as Server", command=self.start_server)
        self.server_button.pack(fill='x', padx=5, pady=5)

        self.status_label = ttk.Label(self, text="Not connected", foreground="#FF3333")
        self.status_label.pack(padx=5, pady=5, anchor='w')

        ttk.Label(self, text="Chat:").pack(padx=5, pady=5, anchor='w')
        self.chat_text = scrolledtext.ScrolledText(self, height=5, bg="#111111", fg="#39FF14",
                                                   font=("Consolas", 12), state='disabled')
        self.chat_text.pack(fill='both', expand=True, padx=5, pady=5)

        ttk.Label(self, text="Message:").pack(padx=5, pady=5, anchor='w')
        self.chat_entry = ttk.Entry(self, font=("Consolas", 12))
        self.chat_entry.pack(fill='x', padx=5, pady=5)
        self.chat_entry.bind('<Return>', lambda e: self.send_chat_message())

        self.send_button = ttk.Button(self, text="Send", command=self.send_chat_message)
        self.send_button.pack(fill='x', padx=5, pady=5)

    # Networking
    def start_server(self):
        port = int(self.port_entry.get())
        threading.Thread(target=self._server_thread, args=(port,), daemon=True).start()

    def _server_thread(self, port):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('', port)); server_sock.listen(1)
            self.append_chat(f"[SYSTEM] Listening on {port}...")
            conn, addr = server_sock.accept()
            self.sock = conn
            self.status_label.config(text=f"Connected {addr[0]}:{addr[1]}", foreground="#33FF33")
            self.append_chat(f"[SYSTEM] Connection from {addr[0]}:{addr[1]}")

            self.aes_key = perform_dh_handshake(conn, is_server=True)
            self.append_chat("[SYSTEM] AES session key established (CBC)")
            self.listen_for_messages()
        except Exception as e:
            self.append_chat(f"[SYSTEM] Server error: {e}")

    def connect_to_peer(self):
        ip = self.peer_ip_entry.get().strip()
        port = int(self.port_entry.get())
        threading.Thread(target=self._client_thread, args=(ip, port), daemon=True).start()

    def _client_thread(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            self.sock = sock
            self.status_label.config(text=f"Connected to {ip}:{port}", foreground="#33FF33")
            self.append_chat(f"[SYSTEM] Connected to {ip}:{port}")

            self.aes_key = perform_dh_handshake(sock, is_server=False)
            self.append_chat("[SYSTEM] AES session key established (CBC)")
            self.listen_for_messages()
        except Exception as e:
            self.append_chat(f"[SYSTEM] Connection failed: {e}")

    def listen_for_messages(self):
        def _listen():
            while self.running and self.sock:
                try:
                    length_bytes = recvall(self.sock, 4)
                    if not length_bytes: break
                    msg_len = int.from_bytes(length_bytes, 'big')
                    data = recvall(self.sock, msg_len)
                    if not data: break

                    glyph_message = data.decode('utf-8')
                    plaintext = decrypt_message(from_glyph_base64(glyph_message), self.aes_key)
                    self.append_chat(f"Peer: {plaintext if plaintext else '[Decryption Failed]'}")
                except Exception as e:
                    self.append_chat(f"[SYSTEM] Receive error: {e}")
                    break
            self.append_chat("[SYSTEM] Connection closed.")
            self.status_label.config(text="Not connected", foreground="#FF3333")
            self.sock = None

        threading.Thread(target=_listen, daemon=True).start()

    def send_chat_message(self):
        if not self.sock or not self.aes_key: return
        msg = self.chat_entry.get().strip()
        if not msg: return
        try:
            encrypted_b64 = encrypt_message(msg, self.aes_key)
            glyph_message = to_glyph_base64(encrypted_b64)
            data = glyph_message.encode('utf-8')
            self.sock.sendall(len(data).to_bytes(4, 'big') + data)
            self.append_chat(f"You: {msg}")
            self.chat_entry.delete(0, tk.END)
        except Exception as e:
            self.append_chat(f"[SYSTEM] Send error: {e}")

    def append_chat(self, text):
        self.chat_text.config(state='normal')
        self.chat_text.insert(tk.END, text + "\n")
        self.chat_text.see(tk.END)
        self.chat_text.config(state='disabled')

    def on_close(self):
        self.running = False
        if self.sock:
            try: self.sock.close()
            except: pass
        self.destroy()

if __name__ == "__main__":
    app = GhostLayersChat()
    app.mainloop()