from flask import Flask #importing flask
from flask import send_file
mudserver = Flask(__name__)

@mudserver.route('/<path:name>', methods=['GET', 'POST']) #get URL that contains IoT device name
#format of URL is 127.0.0.1:43/device_nam


def downloadFile (name):#function that fetches and sends the desired MUD files

    if(name[-3 :] != "pem"):
        filepath = "mudfs-dir/" + name + ".json" 
    else:
        filepath = "mudfs-dir/" + name 
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    mudserver.run(debug=True, port = 443)#running the server on port 443(HTTP)