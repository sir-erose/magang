from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5

# 1. Masukkan teks kunci privat RSA yang didapatkan dari CyberChef
private_key_text = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCpb0jcnaoWeCo9
MwdQnXjnNIYt9fWbyJF+Cktimf+53tYa9YXGHv2+lYbL9QmTzF/hCSpanl5WAat3
GAnEmVc28XEb3FVO9L9fyy+dkBFRZlgiPwCYzpBc3txbMMLjd8lvqdletrxlFI8P
b8AaHQ8UiCF6h40/qFRJFvsf45+tpzgh7qwmJqapREARujBCwmgSZZqaMs2JDIpx
ZlSy9kN0M9DcFYC/zVAvLEVGZRbTJK2ZXRrdYusa19sJfgGU/JLA7jaVsdlUrd2A
hZHf6Gh+NIiWjJVDpT7DcYpBH8HGu//B9JYbSRS1mK7jmIYSicdi8FECHT80DhMo
USjU/kLNAgMBAAECggEANDw7RcyTreaw+voa5LcPmZP/U/cSl8rvU+C/me/pP3fc
ISaVbd2LE/EMRB/QqpCk9H87YAGYCsLsBkTSahpuIWGxIco9QKDCyTkefmB2flZj
kHdE61cveXo5jCGNy8vXvcWq3oDOtwjuC+/DVSmlRwqq65gTq07tYTUlCZFG3qWA
+VPHMdgMjNd7kGgSpDwDCT6HopMrPca5OB0uzukmAifaHEd++1e1/zerNJY0aFVd
mNk4IZ8fQXXmVVMjiCIseUjuPLWUsKyKhMVBLdcHmgqzfkxZBslj3/bi1mpMY1XO
l9uSi6kCb/G0ABo6zzILgfPUpOO6nlvyWvb9c+JijwKBgQDWDjuR8ONgtv6rnaJr
jEMlkjk1hPzQP3cbpPnvhvv3RFwFLxLO4zQS+QjXr6Xv7qVwPFJ5iDLwBPO6piug
SWfWCCcLJVLfCZ5D3Un+pIb0UtwaNe6yjO24id1S7Q8jmsR7iqVT4z8xUkfnF71U
veOIoHWi0sytw5nY/74M6p5QWwKBgQDKorbNRyTfMMF0JS+YNdvFBAPQHXfaSthJ
2ORy2sx52OmtM6Uz3M4iSAbmzCQdzrAPT1wZ9rg/JM1hHLJ0nT1Kb1XBmdf7Upcw
wqok91m04FoAeVa7CNdoTjWgn05/GIWHGLO5TjLTQLK3pNqKkc4d0Qoj6nI1Qrtc
2E8wrxkh9wKBgDfYWr5GhGvVEjgf1iIM4+/HaFmIKpUCGccCkZpmMxJdqUxI7bVA
HXPduOrcjoQ8VLklY7cFS5THFfdaJwOYYxi548XKpQY/ciTudMGUlwjjHT1RWMcI
cXS1syJRaqO1WxGIKH3sSa5KcyvdS63yJIyeoFIsgO3MnDS69BBWnZsFAoGBAJqR
ic2GUkrpvvdgkjCSDMT47gunHtBlvRx/lKtD2Sus2Xrj5UVtTdP6i0EsQPR3v/a9
u2yWtS59XSiRolKvypvn10tplcXA11E7fFvcThJZ/G1WIWFkOiP3XJLcUh1C0EAg
CJ/2VXCtbmYFGysOU2KNHSYOZPXZpGALJETnm807AoGAKI9qU/hofMyrA8ra3VS5
JyixtUvrcctp06VJCUf+pjQ4HL5mlIKOs3HSkPtjIvwyEwKWqa5f1+uUcpjN6QW1
lgNCMvaEqInwHxWAGks9M9ODNomdDb4KU5YM2qCnOWPEkTlqkBGvW/KuAzDsvcdj
UdQF8W94D0ed65jYwpg9/hM=
-----END PRIVATE KEY-----"""

key = RSA.import_key(private_key_text)

# 2. Membaca data biner terenkripsi dari berkas flag.enc
with open("flag.enc", "rb") as f:
    ciphertext = f.read()

# 3. Mencoba dekripsi dengan OAEP (Skema Modern)
try:
    cipher_oaep = PKCS1_OAEP.new(key)
    flag = cipher_oaep.decrypt(ciphertext)
    print(f"[+] Berhasil (OAEP): {flag.decode('utf-8')}")
except Exception:
    # 4. Fallback ke PKCS1_v1_5 jika OAEP gagal (Skema Klasik)
    cipher_v15 = PKCS1_v1_5.new(key)
    sentinel = b"FAILED"
    flag = cipher_v15.decrypt(ciphertext, sentinel)
    print(f"[+] Berhasil (PKCS1_v1_5): {flag.decode('utf-8')}")