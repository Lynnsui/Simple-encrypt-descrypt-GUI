import base64
import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Konfigurasi AES
ALGO = "AES"
MODE = AES.MODE_ECB
PADDING = 'pkcs7'
BLOCK_SIZE = 16  # Ukuran blok untuk AES

class EnkripsiDekripsiGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enkripsi dan Dekripsi Pesan")

        mainframe = ttk.Frame(root, padding="10 10 10 10")
        mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(mainframe, text="Pesan:").grid(column=1, row=1, sticky=tk.W)
        self.pesanField = ttk.Entry(mainframe, width=30)
        self.pesanField.grid(column=2, row=1, sticky=(tk.W, tk.E))

        ttk.Label(mainframe, text="Kunci:").grid(column=1, row=2, sticky=tk.W)
        self.kunciField = ttk.Entry(mainframe, width=30)
        self.kunciField.grid(column=2, row=2, sticky=(tk.W, tk.E))

        self.enkripsiButton = ttk.Button(mainframe, text="Enkripsi", command=self.enkripsi)
        self.enkripsiButton.grid(column=1, row=3, sticky=tk.W)

        self.dekripsiButton = ttk.Button(mainframe, text="Dekripsi", command=self.dekripsi)
        self.dekripsiButton.grid(column=2, row=3, sticky=tk.W)

        self.hasilArea = scrolledtext.ScrolledText(mainframe, width=40, height=10, wrap=tk.WORD)
        self.hasilArea.grid(column=1, row=4, columnspan=2, sticky=(tk.W, tk.E))

        self.statusLabel = ttk.Label(mainframe, text=" ")
        self.statusLabel.grid(column=1, row=5, columnspan=2, sticky=(tk.W, tk.E))

        for child in mainframe.winfo_children(): 
            child.grid_configure(padx=5, pady=5)

        self.pesanField.focus()

    def enkripsi(self):
        pesan = self.pesanField.get()
        kunci = self.generate_random_key()
        self.kunciField.insert(0, kunci)
        try:
            hasil_enkripsi = self.enkripsi_pesan(pesan, kunci)
            self.hasilArea.delete(1.0, tk.END)
            self.hasilArea.insert(tk.END, "Hasil Enkripsi:\n" + hasil_enkripsi)
            self.statusLabel.config(text=" ")
        except Exception as ex:
            self.statusLabel.config(text="Gagal enkripsi: " + str(ex))

    def dekripsi(self):
        pesan_terenkripsi = self.pesanField.get()
        kunci = self.kunciField.get()
        try:
            hasil_dekripsi = self.dekripsi_pesan(pesan_terenkripsi, kunci)
            self.hasilArea.delete(1.0, tk.END)
            self.hasilArea.insert(tk.END, "Hasil Dekripsi:\n" + hasil_dekripsi)
            self.statusLabel.config(text=" ")
        except Exception as ex:
            self.statusLabel.config(text="Gagal dekripsi: " + str(ex))

    def enkripsi_pesan(self, pesan, kunci):
        cipher = AES.new(kunci.encode('utf-8'), MODE)
        encrypted_data = cipher.encrypt(pad(pesan.encode('utf-8'), BLOCK_SIZE, style=PADDING))
        return base64.b64encode(encrypted_data).decode('utf-8')

    def dekripsi_pesan(self, pesan_terenkripsi, kunci):
        cipher = AES.new(kunci.encode('utf-8'), MODE)
        decoded_data = base64.b64decode(pesan_terenkripsi)
        decrypted_data = unpad(cipher.decrypt(decoded_data), BLOCK_SIZE, style=PADDING)
        return decrypted_data.decode('utf-8')

    def generate_random_key(self):
        random_key = random.randint(10000, 99999)
        return str(random_key).zfill(16)

if __name__ == "__main__":
    root = tk.Tk()
    EnkripsiDekripsiGUI(root)
    root.mainloop()