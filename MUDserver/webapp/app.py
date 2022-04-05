from flask import Flask
from flask import send_file
app = Flask(__name__)

@app.route('/<path:name>', methods=['GET', 'POST'])
def downloadFile (name):
    #path = "mudfs-dir/sample/test.json"
    path = "mudfs-dir/" + name + ".json"
    return send_file(path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port = 443)