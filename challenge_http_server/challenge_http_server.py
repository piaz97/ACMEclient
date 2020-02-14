from flask import Flask
from flask import request
from os.path import join, dirname, realpath

app = Flask(__name__)


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app.route('/')
def home_page():
    return "Hello World"


@app.route('/shutdown', methods=['POST', 'GET'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


@app.route('/.well-known/acme-challenge/<token>', methods=['GET', 'POST'])
def get_token(token):

    path = join(dirname(realpath(__file__)), 'challenge_tokens/'+token)

    with open(path, "r") as file:
        key_auth = file.read()

    data = key_auth
    response = app.response_class(
        response= data.encode("ASCII"),
        status=200,
        mimetype='application/octet-stream'
    )

    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5002")
    print("HTTP server starting")


