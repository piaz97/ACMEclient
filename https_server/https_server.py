from flask import Flask
from os.path import join, dirname, realpath
from flask import request

HTTPS_SERVER_CERTIFICATE_PATH = join(dirname(realpath(__file__)), "sec/cert.pem")
HTTPS_SERVER_KEY_PATH = join(dirname(realpath(__file__)), "sec/key.pem")


app = Flask(__name__, instance_relative_config=True)


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app.route('/', methods=["GET"])
def home_page():
    return "I'm a super secure server ;)"


@app.route('/shutdown', methods=['POST'])
def shutdown():
    shutdown_server()
    return 'Server shutting down...'


if __name__ == "__main__":
    print("HTTPS server is UP\n")
    app.run(host="0.0.0.0", port="5001", ssl_context=(HTTPS_SERVER_CERTIFICATE_PATH, HTTPS_SERVER_KEY_PATH))


