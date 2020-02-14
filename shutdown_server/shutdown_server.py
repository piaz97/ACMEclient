from flask import Flask
from flask import request
import os
import sys
import requests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from dns_server.dns_server import MyDNSServer

app = Flask(__name__)

dns_server = MyDNSServer()


def shutdown_server():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()


@app.route('/start', methods=['GET', 'POST'])
def home_page():
    address = request.args.get('address')
    dns_server.start(address)
    return "DNS server started"


@app.route('/shutdown', methods=['GET', 'POST'])
def shutdown():
    print('Shutting down all the servers')
    # shutting down the DNS
    dns_server.shut_down()

    requests.post("http://0.0.0.0:5002/shutdown", verify=False)
    requests.post("https://0.0.0.0:5001/shutdown", verify=False)

    shutdown_server()
    return 'Server shutting down...'


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5003")


