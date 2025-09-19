import hashlib
import itertools
import string
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

SUPPORTED_HASHES = [
    'md5',
    'sha1',
    'sha224',
    'sha256',
    'sha384',
    'sha3_224',
    'sha3_256',
    'sha3_384',
    'sha3_512',
    'sha512'
]


def crack_hash(hash_value, hash_type, min_len, max_len, charset, wordlist_path, progress_callback, result_callback):
    """
    This runs in a background thread. It calls:
     - progress_callback(tried, total) periodically
     - result_callback(password_or_None) when done
    """
    try:
        hash_fn = getattr(hashlib, hash_type, None)
        if hash_fn is None:
            result_callback(None, f"Unsupported hash type: {hash_type}")
            return

        # Try wordlist first (if provided)
        if wordlist_path:
            try:
                with open(wordlist_path, "r", errors="ignore", encoding="utf-8") as f:
                    lines = (line.strip() for line in f)
                    lines = [ln for ln in lines if ln]  # filter empties
            except Exception as e:
                result_callback(None, f"Failed to read wordlist: {e}")
                return

            total = len(lines)
            tried = 0
            for candidate in lines:
                tried += 1
                if hash_fn(candidate.encode()).hexdigest() == hash_value:
                    result_callback(candidate, None)
                    return
                if tried % 50 == 0:
                    progress_callback(tried, total)

        # Brute-force
        total = 0
        for L in range(min_len, max_len + 1):
            total += len(charset) ** L

        tried = 0
        for length in range(min_len, max_len + 1):
            for tup in itertools.product(charset, repeat=length):
                tried += 1
                candidate = ''.join(tup)
                if hash_fn(candidate.encode()).hexdigest() == hash_value:
                    result_callback(candidate, None)
                    return
                if tried % 100 == 0:
                    progress_callback(tried, total)

        # Not found
        result_callback(None, None)
    except Exception as e:
        result_callback(None, f"Error during cracking: {e}")


class HashCrackerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Hash Cracker")
        self.geometry("540x420")
        self.resizable(False, False)
        self.wordlist_path = None
        self.create_widgets()

    def create_widgets(self):
        pad = {'padx': 10, 'pady': 6}

        ttk.Label(self, text="Hash Value:").grid(row=0, column=0, sticky="w", **pad)
        self.hash_entry = ttk.Entry(self, width=55)
        self.hash_entry.grid(row=0, column=1, columnspan=2, **pad)

        ttk.Label(self, text="Hash Type:").grid(row=1, column=0, sticky="w", **pad)
        self.hash_type = tk.StringVar()
        self.hash_menu = ttk.Combobox(self, textvariable=self.hash_type,
                                      values=SUPPORTED_HASHES, state="readonly", width=25)
        self.hash_menu.set('')  # no default selected
        self.hash_menu.grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(self, text="Min Length:").grid(row=2, column=0, sticky="w", **pad)
        self.min_len = ttk.Entry(self, width=10)
        self.min_len.grid(row=2, column=1, sticky="w", **pad)

        ttk.Label(self, text="Max Length:").grid(row=3, column=0, sticky="w", **pad)
        self.max_len = ttk.Entry(self, width=10)
        self.max_len.grid(row=3, column=1, sticky="w", **pad)

        ttk.Label(self, text="Character Set:").grid(row=4, column=0, sticky="w", **pad)
        self.charset = tk.StringVar(value="")  # no default; user must enter
        ttk.Entry(self, textvariable=self.charset, width=50).grid(row=4, column=1, columnspan=2, **pad)

        self.wordlist_btn = ttk.Button(self, text="Choose Wordlist (optional)", command=self.choose_wordlist)
        self.wordlist_btn.grid(row=5, column=0, columnspan=1, **pad)
        self.wordlist_label = ttk.Label(self, text="No wordlist selected", width=40)
        self.wordlist_label.grid(row=5, column=1, columnspan=2, sticky="w", **pad)

        self.start_btn = ttk.Button(self, text="Start Cracking", command=self.start_cracking)
        self.start_btn.grid(row=6, column=0, columnspan=3, pady=(10, 2))

        self.progress = ttk.Progressbar(self, length=480, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=3, **pad)

        self.status = ttk.Label(self, text="Status: Waiting for input", anchor="w")
        self.status.grid(row=8, column=0, columnspan=3, sticky="w", **pad)

    def choose_wordlist(self):
        path = filedialog.askopenfilename(title="Select Wordlist File")
        if path:
            self.wordlist_path = path
            self.wordlist_label.config(text=os.path.basename(path))

    def start_cracking(self):
        hash_value = self.hash_entry.get().strip()
        h_type = self.hash_type.get().strip()
        try:
            min_len = int(self.min_len.get().strip())
            max_len = int(self.max_len.get().strip())
        except ValueError:
            messagebox.showwarning("Invalid Input", "Min and Max length must be integer numbers.")
            return
        charset = self.charset.get()
        if not hash_value:
            messagebox.showwarning("Missing Data", "Please enter the hash value.")
            return
        if h_type not in SUPPORTED_HASHES:
            messagebox.showwarning("Unsupported Hash", "Please select a supported hash type from the dropdown.")
            return
        if not charset:
            messagebox.showwarning("Missing Data", "Please enter a character set for brute-force (e.g. abcdef...0123).")
            return
        if min_len <= 0 or min_len > max_len:
            messagebox.showwarning("Invalid Range", "Min length must be > 0 and <= Max length.")
            return

        # Reset UI
        self.progress['value'] = 0
        self.progress['maximum'] = 1
        self.status.config(text="Cracking started...")
        self.start_btn.config(state="disabled")

        # Start background thread
        threading.Thread(
            target=crack_hash,
            args=(hash_value, h_type, min_len, max_len, charset, self.wordlist_path,
                  self.thread_safe_progress, self.thread_safe_result),
            daemon=True
        ).start()

    # Thread-safe UI update wrappers
    def thread_safe_progress(self, tried, total):
        # schedule UI update on main thread
        self.after(0, lambda: self.update_progress(tried, total))

    def thread_safe_result(self, password, error_message):
        self.after(0, lambda: self.show_result(password, error_message))

    def update_progress(self, tried, total):
        self.progress['maximum'] = total if total > 0 else 1
        self.progress['value'] = tried
        self.status.config(text=f"Checked {tried}/{total} combinations")

    def show_result(self, password, error_message):
        self.start_btn.config(state="normal")
        if error_message:
            messagebox.showerror("Error", error_message)
            self.status.config(text=f"Error: {error_message}")
            return
        if password:
            messagebox.showinfo("Success", f"Password found: {password}")
            self.status.config(text=f"Password found: {password}")
        else:
            messagebox.showinfo("Result", "Password not found.")
            self.status.config(text="Password not found.")


if __name__ == "__main__":
    app = HashCrackerApp()
    app.mainloop()
