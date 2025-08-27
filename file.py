# Hardcoded inputs
file_name = "encoded.txt"
platform = "Platform"
encrypted_string = "Encrypted TOTP url"

with open(file_name, "a") as f:
    f.write(f"{platform}, {encrypted_string}\n")

print("Entry added")
