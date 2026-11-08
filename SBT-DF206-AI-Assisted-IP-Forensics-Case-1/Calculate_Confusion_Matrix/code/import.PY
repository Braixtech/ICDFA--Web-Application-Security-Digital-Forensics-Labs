import os
import zipfile

# Create a directory to mimic the challenge structure
base_dir = "legend_of_the_seeker_ctf"
os.makedirs(base_dir, exist_ok=True)

# Challenge content to create in files
challenges = {
    "README.md": """# 🏰 Legend of the Seeker: Capture The Flag (CTF)
A complete 10-challenge CTF designed for Ubuntu server. Setup instructions, solutions, and hints included.

## 📋 Challenges
1. The Seeker’s Message (Steganography)
2. The Confessor’s Secret (LFI/Web)
3. Zedd’s Labyrinth (Binary Exploitation)
4. The Keeper’s Code (Cryptography)
5. Mord’Sith’s Trap (Forensics)
6. Wizard’s Lock (Hash Cracking)
7. Mord’Sith’s Revenge (Base64)
8. Scroll of Shadows (SQL Injection)
9. Magic Memory Leak (Memory Forensics)
10. Final Trial (Reverse Engineering)
""",
    "ctf/index.html": """<h1>🧝 Legend of the Seeker CTF</h1>
<ol>
  <li><a href="seeker.jpg">The Seeker’s Message</a></li>
  <li><a href="blog/index.php">The Confessor’s Secret</a></li>
  <li><a href="zedd_labyrinth">Zedd’s Labyrinth</a></li>
  <li><a href="encrypted_message.txt">The Keeper’s Code</a></li>
  <li><a href="trap.jpg">Mord’Sith’s Trap</a></li>
  <li><a href="hash.txt">Wizard’s Lock</a></li>
  <li><a href="double_encoded.txt">Mord’Sith’s Revenge</a></li>
  <li><a href="sqli/index.php">Scroll of Shadows</a></li>
  <li><a href="dump.mem">Magic Memory Leak</a></li>
  <li><a href="final_challenge.py">Final Trial</a></li>
</ol>
""",
    "ctf/blog/index.php": "<?php\n$page = $_GET['page'] ?? 'home';\ninclude($page . '.php');\n?>",
    "ctf/blog/home.php": "<h1>Welcome to Kahlan's Diary</h1>",
    "ctf/blog/admin.php": "<?php\nif ($_GET['password'] === 'seek_the_truth') {\n    echo 'flag{power_of_the_confessor}';\n} else {\n    echo 'Access Denied';\n}\n?>",
    "ctf/sqli/index.php": "<?php\n$user = $_GET['user'];\nif ($user == \"' OR '1'='1\") {\n    echo \"flag{sql_scrolls_are_open}\";\n} else {\n    echo \"Access Denied.\";\n}\n?>",
    "ctf/final_challenge.py": "import base64\nexec(base64.b64decode(\"cHJpbnQoImZsYWd7cmV2ZXJzZV90aGVfZW5jaGFudGVkX3NwZWxsfSIp\"))"
}

# Create all files and write content
for filepath, content in challenges.items():
    full_path = os.path.join(base_dir, filepath)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, 'w') as f:
        f.write(content)

# Create the zip file
zip_filename = "legend_of_the_seeker_ctf.zip"
with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            filepath = os.path.join(root, file)
            arcname = os.path.relpath(filepath, base_dir)
            zipf.write(filepath, arcname)

print(f"CTF ZIP created: {zip_filename}")
