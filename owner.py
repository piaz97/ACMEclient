from acme_client.ACMEclient import *
from os.path import join, dirname, realpath
from time import sleep
import requests
import subprocess
import argparse


def add_token_to_http_server(authorization_entry):
    token = None
    for auth in authorization_entry["challenges"]:
        if auth["type"] == "http-01":
            token = auth["token"]
    if token is not None:
        file_path = join(dirname(realpath(__file__)), 'challenge_http_server/challenge_tokens/'+token)
        with open(file_path, "w+") as file:
            file.write(get_key_auth_from_token(token))
        return True
    else:
        return False


def add_token_to_dns_server(authorization_entry):
    token = None
    wildcard = False
    for auth in authorization_entry["challenges"]:
        if auth["type"] == "dns-01":
            token = auth["token"]
        if "wildcard" in authorization_entry:
            wildcard = True

    domain = authorization_entry["identifier"]["value"]
    if token is not None:
        if wildcard:
            file_path = join(dirname(realpath(__file__)), 'dns_server/challenge_tokens/'+'wildcard_acme-challenge.'+domain)
        else:
            file_path = join(dirname(realpath(__file__)), 'dns_server/challenge_tokens/' + '_acme-challenge.' + domain)
        with open(file_path, "w+") as file:
            file.write(get_dns_key_from_token(token))


def respond_challenge(authorization_entry, challenge_type):
    challenge_url = None
    for auth in authorization_entry["challenges"]:
        if auth["type"] == challenge_type:
            challenge_url = auth["url"]
    if challenge_url is not None:
        try:
            return post_as_get(challenge_url, "challenge")
        except Exception as err:
            return err


def check_challenge_status(auth_url):
    try:
        return post_as_get(auth_url, "status")
    except Exception as err:
        return err


def download_certificate(url):
    try:
        return post_as_get(url, "cert")
    except Exception as err:
        return err


# main
if __name__ == "__main__":
    print("Application started \n \n")
    parser = argparse.ArgumentParser(description='ACME client project')
    parser.add_argument('challenge_type')
    parser.add_argument('--dir')
    parser.add_argument('--domain', action='append')
    parser.add_argument('--revoke', action='store_true')
    parser.add_argument('--record')

    args = parser.parse_args()

    challenge_type = args.challenge_type
    domains = args.domain
    revoke = args.revoke
    directory = args.dir
    address = args.record

    requests.get("http://0.0.0.0:5003/start?address="+address)

    # call the start function on shutdown server
    get_directory(directory)

    [order, key] = create_account()

    order_response = submit_order(domains)

    finalize_url = order_response["finalize"]

    authorizations_urls = order_response["authorizations"]

    # authorization are a JSON with three fields, challenges, expires and status
    authorizations = fetch_challenges(authorizations_urls)

    # [print(json.dumps(x, indent=4, sort_keys=True)) for x in authorizations]
    sleep(1)
    for authorization in authorizations:
        if challenge_type == "dns01":
            add_token_to_dns_server(authorization)
        elif challenge_type == "http01":
            add_token_to_http_server(authorization)
        else:
            raise Exception("Challenge type not recognized")

    for authorization in authorizations:
        if challenge_type == "dns01":
            respond_challenge(authorization, "dns-01")
        elif challenge_type == "http01":
            print(respond_challenge(authorization, "http-01"))
        else:
            raise Exception("Challenge type not recognized")

    # polling

    for authorization_url in authorizations_urls:
        res = check_challenge_status(authorization_url)
        while res["status"] != "valid":
            print("waiting for: "+str(authorization_url), "status: "+res["status"])
            sleep(1)
            res = check_challenge_status(authorization_url)

        print("CHALLENGE: "+str(authorization_url)+" \t\tok \n")

    res = finalize(domains, finalize_url)

    myOrder = check_challenge_status(order["orders"])["orders"][0]

    while res["status"] != "valid":
        print("waiting for certificate, current status: "+res["status"])
        sleep(1)
        res = check_challenge_status(myOrder)

    print("CERTIFICATE READY TO BE DOWNLOADED FROM: "+res["certificate"])

    cert = download_certificate(res["certificate"]).text

    # the certificate chain is obtained, that is, all the CAs chain that took a part in validating this csr will be
    # linked to the new certificate. in this way, a client will have all the necessary certificate to check the validity
    # of the server certificate, and will be much faster in establishing a TLS connection

    cert_path = join(dirname(realpath(__file__)), 'https_server/sec/cert.pem')
    key_path = join(dirname(realpath(__file__)), 'https_server/sec/key.pem')

    with open(cert_path, "wb+") as cert_file:
        cert_file.write(bytes(cert, "ASCII"))

    with open(key_path, "wb+") as key_file:
        key_file.write(bytes(key, "ASCII"))

    # starting the https server
    https_path = join(dirname(realpath(__file__)), 'https_server/https_server.py')
    process = subprocess.Popen('python3 '+https_path, shell=True)
    
    if revoke:
        revoke_cert()
        print("Certificate revoked")
    # wait the https server to be closed
    process.wait()

