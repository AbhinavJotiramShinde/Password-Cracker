import hashlib
import itertools
import string
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------- Hash cracking logic ----------
def crack_hash(hash_value, hash_type, min_len, max_len, charset, wordlist_path, progress_callback, result_callback):
    found = None

    try:
        # Optional wordlist first
        if wordlist_path:
            with open(wordlist_path, "r", errors="ignore") as f:
                for line in f:
                    candidate = line.strip()
                    if getattr(hashlib, hash_type)(candidate.encode()).hexdigest() == hash_value:
                        found = candidate
                        result_callback(found)
                        return

        total = sum(len(charset)**l for l in range(min_len, max_len+1))
        tried = 0

        for length in range(min_len, max_len+1):
            for pwd_tuple in itertools.product(charset, repeat=length):
                candidate = ''.join(pwd_tuple)
                tried += 1
                if getattr(hashlib, hash_type)(candidate.encode()).hexdigest() == hash_value:
                    found = candidate
                    result_callback(found)
                    return
                progress_callback(tried, total)
        result_callback(None)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# ---------- GUI ----------
class HashCrackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Cracker")
        self.geometry("450x400")
        self.resizable(False, False)

        self.wordlist_path = None
        self.create_widgets()

    def create_widgets(self):
        pad = {'padx': 10, 'pady': 5}

        ttk.Label(self, text="Hash Value:").grid(row=0, column=0, sticky="w", **pad)
        self.hash_entry = ttk.Entry(self, width=50)
        self.hash_entry.grid(row=0, column=1, **pad)

        ttk.Label(self, text="Hash Type:").grid(row=1, column=0, sticky="w", **pad)
        self.hash_type = tk.StringVar()
        self.hash_menu = ttk.Combobox(self, textvariable=self.hash_type,
                                      values=hashlib.algorithms_guaranteed, state="readonly")
        self.hash_menu.grid(row=1, column=1, **pad)

        ttk.Label(self, text="Min Length:").grid(row=2, column=0, sticky="w", **pad)
        self.min_len = ttk.Entry(self, width=10)
        self.min_len.grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(self, text="Max Length:").grid(row=3, column=0, sticky="w", **pad)
        self.max_len = ttk.Entry(self, width=10)
        self.max_len.grid(row=3, column=1, sticky="w", **pad)

        ttk.Label(self, text="Character Set:").grid(row=4, column=0, sticky="w", **pad)
        self.charset = tk.StringVar(value=string.ascii_lowercase + string.digits)
        ttk.Entry(self, textvariable=self.charset, width=50).grid(row=4, column=1, **pad)

        self.wordlist_btn = ttk.Button(self, text="Choose Wordlist (optional)", command=self.choose_wordlist)
        self.wordlist_btn.grid(row=5, column=0, columnspan=2, **pad)

        self.start_btn = ttk.Button(self, text="Start Cracking", command=self.start_cracking)
        self.start_btn.grid(row=6, column=0, columnspan=2, **pad)

        self.progress = ttk.Progressbar(self, length=400, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=2, **pad)

        self.status = ttk.Label(self, text="Status: Waiting for input")
        self.status.grid(row=8, column=0, columnspan=2, **pad)

    def choose_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist File")
        if path:
            self.wordlist_path = path
            self.wordlist_btn.config(text=f"Wordlist: {path.split('/')[-1]}")

    def start_cracking(self):
        hash_value = self.hash_entry.get().strip()
        h_type = self.hash_type.get().strip()
        try:
            min_len = int(self.min_len.get().strip())
            max_len = int(self.max_len.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid Input", "Min and Max length must be integers.")
            return
        charset = self.charset.get().strip()

        if not hash_value or not h_type or not charset:
            messagebox.showwarning("Missing Data", "Please fill in all required fields.")
            return
        if min_len > max_len or min_len <= 0:
            messagebox.showwarning("Invalid Range", "Min length must be <= Max length and > 0.")
            return

        self.status.config(text="Cracking in progress...")
        self.progress['value'] = 0

        threading.Thread(
            target=crack_hash,
            args=(hash_value, h_type, min_len, max_len, charset,
                  self.wordlist_path, self.update_progress, self.show_result),
            daemon=True
        ).start()

    def update_progress(self, tried, total):
        self.progress['maximum'] = total
        self.progress['value'] = tried
        self.status.config(text=f"Checked {tried}/{total} combinations")

    def show_result(self, password):
        if password:
            messagebox.showinfo("Success", f"Password found: {password}")
            self.status.config(text=f"Password found: {password}")
        else:
            messagebox.showinfo("Result", "Password not found.")
            self.status.config(text="Password not found.")

if __name__ == "__main__":
    app = HashCrackerApp()
    app.mainloop()
