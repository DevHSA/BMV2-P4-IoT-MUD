from flask import Flask #importing flask
from flask import send_file
fileserver = Flask(__name__)

@fileserver.route('/<path:name>', methods=['GET', 'POST']) #get URL that contains IoT device name
#format of URL is 127.0.0.1:443/device_name

def downloadFile (name):#function that fetches and sends the desired MUD files

    filepath = "mudfs-dir/" + name + ".json" 
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    fileserver.run(debug=True, port = 443)#running the server on port 443(HTTP)