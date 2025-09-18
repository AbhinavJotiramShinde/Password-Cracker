#  Multi-Threaded Hash Cracker

A simple **multi-threaded hash-cracking tool** that can recover plaintext passwords from a given hash using either:
- **Dictionary (wordlist) attacks**, or
- **Brute-force attacks** with configurable character sets and lengths.

It supports multiple hashing algorithms out-of-the-box.

---

##  Features
-  Supports popular hash types: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `sha512`
-  Dictionary (wordlist) mode **or** brute-force mode
-  Multi-threaded for faster cracking using `ThreadPoolExecutor`
-  Progress bars using `tqdm`

---

##  Requirements

- Python 3.7+
- [tqdm](https://pypi.org/project/tqdm/)

Install dependencies:
pip install tqdm

Usage
 Dictionary / Wordlist Attack
 Crack a hash by testing each password from a wordlist.

python hash_cracker.py <hash> -w <wordlist_path> --hash_type <hash_type>

Example:
python hash_cracker.py 5d41402abc4b2a76b9719d911017c592 -w rorfrw.txt --hash_type md5
This tries every password in rockyou.txt against the provided MD5 hash.

Brute-Force Attack:
Generate all possible passwords within a length range.

python hash_cracker.py <hash> --hash_type <hash_type> --min_length <min> --max_length <max> [-c <characters>] [--max_workers <threads>]
Example:

python hash_cracker.py 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae \
  --hash_type sha256 \
  --min_length 3 \
  --max_length 4 \
  -c abc123 \
  --max_workers 8
This brute-forces every 3–4 character combination of a b c 1 2 3 using SHA-256 and 8 worker threads.

Arguments
Flag	Description	Default
hash	(positional) The target hash to crack	–
-w, --wordlist	Path to a wordlist file for dictionary attack	None
--hash_type	Hashing algorithm (must be in supported list)	md5
--min_length	Minimum length for brute force	None
--max_length	Maximum length for brute force	None
-c, --characters	Characters used in brute force	Letters + digits
--max_workers	Number of threads to use	4

⚠️ Legal & Ethical Notice
This tool is intended only for educational purposes and for use on hashes you own or are explicitly authorized to test.
Unauthorized password cracking is illegal and punishable by law.

