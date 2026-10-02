"""
Simulasi transmisi ciphertext (DES-CBC) dua arah (Sender <-> Receiver) lewat TCP socket.

Jalankan di dua terminal / dua VM / dua komputer:

  Pihak A (menunggu koneksi):  python peer.py listen 5000
  Pihak B (menyambung):        python peer.py connect 127.0.0.1 5000

Kedua pihak bisa mengirim & menerima pesan secara bersamaan.
Key sudah dipegang kedua pihak (hardcode di bawah), TIDAK dikirim lewat jaringan.
Ketik 'quit' untuk keluar.
"""
import socket
import struct
import sys
import threading

import des

SHARED_KEY = b"KunciDES"  # tepat 8 byte, sudah diketahui kedua pihak


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi terputus")
        buf += chunk
    return buf


def send_message(sock, text, name):
    blob = des.encrypt(text.encode("utf-8"), SHARED_KEY)
    print(f"  [{name}] plaintext  : {text}")
    print(f"  [{name}] ciphertext : {blob.hex()}")
    sock.sendall(struct.pack(">I", len(blob)) + blob)  # framing: 4 byte panjang + data


def receive_loop(sock, name):
    try:
        while True:
            (length,) = struct.unpack(">I", recv_exact(sock, 4))
            blob = recv_exact(sock, length)
            print(f"\n  [{name}] ciphertext diterima: {blob.hex()}")
            try:
                plain = des.decrypt(blob, SHARED_KEY).decode("utf-8")
                print(f"  [{name}] hasil dekripsi     : {plain}")
            except ValueError as e:
                print(f"  [{name}] gagal dekripsi: {e}")
            print("> ", end="", flush=True)
    except (ConnectionError, OSError):
        print(f"\n[{name}] Koneksi ditutup.")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "listen":
        port = int(sys.argv[2])
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        print(f"Menunggu koneksi di port {port} ...")
        sock, addr = srv.accept()
        print(f"Terhubung dengan {addr}")
        name = "A"
    elif mode == "connect":
        host, port = sys.argv[2], int(sys.argv[3])
        sock = socket.create_connection((host, port))
        print(f"Terhubung ke {host}:{port}")
        name = "B"
    else:
        print(__doc__)
        sys.exit(1)

    threading.Thread(target=receive_loop, args=(sock, name), daemon=True).start()

    try:
        while True:
            text = input("> ")
            if text.strip().lower() == "quit":
                break
            if text:
                send_message(sock, text, name)
    except (EOFError, KeyboardInterrupt, OSError):
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
