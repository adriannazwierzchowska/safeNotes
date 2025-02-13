import os
import secrets
import base64

ENV_EXAMPLE = ".env.example"
ENV_FILE = ".env"

def generate_aes_key():
    return base64.b64encode(secrets.token_bytes(32)).decode()

def generate_secret_key():
    return secrets.token_hex(32)

if not os.path.exists(ENV_EXAMPLE):
    print(f"{ENV_EXAMPLE} does not exist.")
    exit(1)

with open(ENV_EXAMPLE, "r") as f:
    env_content = f.readlines()

new_env_content = []
for line in env_content:
    if line.startswith("SECRET_KEY="):
        new_env_content.append(f"SECRET_KEY={generate_secret_key()}\n")
    elif line.startswith("AES_KEY_TOTP="):
        new_env_content.append(f"AES_KEY_TOTP={generate_aes_key()}\n")
    elif line.startswith("AES_KEY_RSA="):
        new_env_content.append(f"AES_KEY_RSA={generate_aes_key()}\n")
    elif line.startswith("AES_KEY_NOTE="):
        new_env_content.append(f"AES_KEY_NOTE={generate_aes_key()}\n")
    else:
        new_env_content.append(line)

with open(ENV_FILE, "w") as f:
    f.writelines(new_env_content)

print(f"Env file {ENV_FILE} has been generated.")
