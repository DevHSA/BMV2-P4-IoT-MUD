"""
------------------------------------------------------

Flask is a micro web framework that is used to create web applications in Python

the mud server is used to create a private MUD file server that advertises 
the MUD files and their corresponding signatures.
It is an HTTPS server that uses port 443.
We need to invoke the mud server and fetch the desired MUD files

------------------------------------------------------

"""

from flask import Flask #importing flask
from flask import send_file #send_file allows us to sent the content of the file to the client
mudserver = Flask(__name__) #this is just a convenient way to get import name of the place the app is defined.

@mudserver.route('/<path:name>', methods=['GET', 'POST']) 

#get URL that contains IoT device name
#format of URL is 127.0.0.1:43/device_name



def downloadFile (name):#function that fetches and sends the desired MUD files

    '''
    ------------------------------------------------------
    mud file and signed mud file have extension .json
    so, when file asked is not a key file, fetch the json files in the mudfs-dir
    else, fetch the pem file in the mudfs-dir
    ------------------------------------------------------
    '''


    if(name[-3 :] != "pem"): #[-3 : ] is to get the last 3 characters of the file asked
        filepath = "mudfs-dir/" + name + ".json" 
    else:
        filepath = "mudfs-dir/" + name 
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    mudserver.run(debug=True, port = 443)#running the server on port 443(HTTP)