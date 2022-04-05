import requests
import subprocess
import os

name = input("Enter name of the device\n")

url = 'http://127.0.0.1:443/' + name
r = requests.get(url, allow_redirects=True)
a = name + '_file.json'
open(a , 'wb').write(r.content)

url2 = 'http://127.0.0.1:443/sign' + name
b = name + '_signfile.json'
s = requests.get(url2, allow_redirects=True)
open(b, 'wb').write(s.content)

url3 = 'http://127.0.0.1:443/pub-key.pem'
t = requests.get(url3, allow_redirects=True)
open('pub-key.pem', 'wb').write(t.content)

try:
	subprocess.check_output(["openssl", "dgst" ,"-sha256", "-verify" ,"/home/p4/IoTMUD/MUDserver/webapp/signaturetest/keys/pub-key.pem", "-signature" , b, a]).decode("utf-8")
	print("Verification successful, please check the folder")
except subprocess.CalledProcessError as e:
	print((e.output).decode("utf-8"))
	os.remove(a)
	os.remove(b)
	os.remove('pub-key.pem')
