import requests
import base64
import json
from datetime import datetime, timezone, timedelta
'''
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
'''
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from os.path import join, dirname, realpath
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

##############################
# ACME SERVER PARAMETERS
##############################

ACME_SERVER_CERTIFICATE_PATH = path = join(dirname(realpath(__file__)), "../pebble_https_ca.pem")

##############################
# ACME SERVER DIRECTORY LINK
##############################

NEW_NONCE_URL = None
NEW_ACCOUNT_URL = None
NEW_ORDER_URL = None
NEW_AUTHZ_URL = None
REVOKE_CERT_URL = None
KEY_CHANGE_URL = None

PRIVATE_KEY = None
NONCE = None
KID = None


def json_to_rfc7519(data):
    # "=" must be stripped manually if necessary RFC-8555
    return (base64.urlsafe_b64encode(bytes(str(data), "UTF-8")).decode("ASCII").strip(
        "="))


def get_directory(url):
    global NEW_NONCE_URL
    global NEW_ACCOUNT_URL
    global NEW_ORDER_URL
    global NEW_AUTHZ_URL
    global REVOKE_CERT_URL
    global KEY_CHANGE_URL

    response = requests.get(url, verify=ACME_SERVER_CERTIFICATE_PATH)

    if response.status_code == 200:
        data = response.json()
        NEW_NONCE_URL = data["newNonce"]
        NEW_ACCOUNT_URL = data["newAccount"]
        NEW_ORDER_URL = data["newOrder"]

        if "newAuthz" in data:
            NEW_AUTHZ_URL = data["newAuthz"]

        REVOKE_CERT_URL = data["revokeCert"]
        KEY_CHANGE_URL = data["keyChange"]
    else:
        response.raise_for_status()


# get a new nonce (not checking if the nonce is already set)
def get_nonce():
    response = requests.get(NEW_NONCE_URL, verify=ACME_SERVER_CERTIFICATE_PATH)

    if response.status_code == 204:
        data = response.headers
        return data["Replay-Nonce"]
    else:
        response.raise_for_status()


def replace_nonce(header):
    global NONCE
    NONCE = header["Replay-Nonce"]
    return


def get_jwk():
    global PRIVATE_KEY

    if PRIVATE_KEY is None:
        raise Exception("Private key not set")

    x = PRIVATE_KEY.pointQ.x
    y = PRIVATE_KEY.pointQ.y

    # RFC 7637 wants the Thumbprint with all the fields ordered lexicographically
    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": base64.urlsafe_b64encode(x.to_bytes()).decode("UTF-8").strip("="),
        "y": base64.urlsafe_b64encode(y.to_bytes()).decode("UTF-8").strip("=")
    }

    return jwk


def get_jws(url, kid=None):
    if kid is None:
        jwk = get_jwk()
        jws = {
            "alg": "ES256",
            "jwk": jwk,
            "nonce": NONCE,
            "url": url
        }
    else:
        jws = {
            "alg": "ES256",
            "kid": kid,
            "nonce": NONCE,
            "url": url
        }

    return jws


def get_signature(jws, payload):
    global PRIVATE_KEY
    if payload is not "":
        payload = json.dumps(payload, separators=(',', ':'))
    jws = json.dumps(jws, separators=(',', ':'))

    if PRIVATE_KEY is None:
        raise Exception("Private key not set")
    else:
        # RFC 7518 => signing a jws #
        message_to_be_signed = json_to_rfc7519(jws) + "." + json_to_rfc7519(payload)

        h = SHA256.new(bytes(message_to_be_signed, "ASCII"))
        signer = DSS.new(PRIVATE_KEY, 'fips-186-3')
        signature = base64.urlsafe_b64encode(signer.sign(h)).decode("ASCII").strip("=")

        return signature


def get_request(jws, payload, signature):
    if payload is not "":
        payload = json.dumps(payload, separators=(',', ':'))
    jws = json.dumps(jws, separators=(',', ':'))
    request_body = {
        "protected": json_to_rfc7519(jws),
        "payload": ("" if payload is "" else json_to_rfc7519(payload)),
        "signature": signature
    }

    request_body = json.dumps(request_body, separators=(',', ':'))

    return request_body


# returns two values [response's json, private_key.pem]
def create_account():
    # KEY GENERATION #
    global PRIVATE_KEY
    global NONCE
    global KID

    # asking for nonce
    NONCE = get_nonce()
    # creating a new key pair
    PRIVATE_KEY = ECC.generate(curve='P-256')

    # setting the jws JSON
    jws = get_jws(NEW_ACCOUNT_URL)

    # preparing the payload
    payload = {
        "termsOfServiceAgreed": True
    }

    # signing
    signature = get_signature(jws, payload)

    # get the request
    request_body = get_request(jws, payload, signature)

    headers = {'Content-type': 'application/jose+json'}

    response = requests.post(NEW_ACCOUNT_URL, data=request_body,
                             headers=headers, verify=ACME_SERVER_CERTIFICATE_PATH)

    data = response.headers
    replace_nonce(data)

    if response.status_code == 201:
        KID = data["Location"]
        return [response.json(), PRIVATE_KEY.export_key(format="PEM")]
    else:
        response.raise_for_status()


def submit_order(domains):
    global KID
    # setting the jws JSON
    jws = get_jws(NEW_ORDER_URL, kid=KID)

    # preparing the payload

    now = datetime.now(timezone.utc).astimezone()
    after_a_week = now + timedelta(weeks=3)
    not_before = now.isoformat()
    not_after = after_a_week.isoformat()

    identifiers = [{"type": "dns", "value": x} for x in domains]

    payload = {
        "identifiers": identifiers,
        "notBefore": not_before,
        "notAfter": not_after
    }

    # signing
    signature = get_signature(jws, payload)

    # get the request
    request_body = get_request(jws, payload, signature)

    headers = {'Content-type': 'application/jose+json'}

    response = requests.post(NEW_ORDER_URL, data=request_body,
                             headers=headers, verify=ACME_SERVER_CERTIFICATE_PATH)

    data = response.headers
    replace_nonce(data)
    if response.status_code == 201:
        return response.json()
    else:
        response.raise_for_status()


def fetch_challenge(authorization_url):
    global KID
    # setting the jws JSON
    jws = get_jws(authorization_url, kid=KID)

    # preparing the payload
    payload = ""

    # signing
    signature = get_signature(jws, payload)

    # get the request
    request_body = get_request(jws, payload, signature)

    headers = {'Content-type': 'application/jose+json'}

    response = requests.post(authorization_url, data=request_body,
                             headers=headers, verify=ACME_SERVER_CERTIFICATE_PATH)

    data = response.headers
    replace_nonce(data)
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def fetch_challenges(authorizations):
    ris = []
    for authorization in authorizations:
        ris.append(fetch_challenge(authorization))
    return ris


# return a bytes string
def get_thumbprint():
    jwk = get_jwk()
    jwk = json.dumps(jwk, separators=(',', ':'))

    h = SHA256.new(bytes(jwk, "ASCII")).digest()
    return h


def get_key_auth_from_token(token):
    return token + "." + base64.urlsafe_b64encode(get_thumbprint()).decode("ASCII").strip(
        "=")


def get_dns_key_from_token(token):
    key_auth = get_key_auth_from_token(token)
    h = SHA256.new(bytes(key_auth, "ASCII")).digest()
    return base64.urlsafe_b64encode(h).decode("ASCII").strip(
        "=")


def post_as_get(challenge_url, scope):
    global KID
    # setting the jws JSON
    jws = get_jws(challenge_url, kid=KID)

    # preparing the payload
    if scope == "challenge":
        payload = {}
    elif scope == "status" or scope == "cert":
        payload = ""
    else:
        raise Exception("invalid scope")

    # signing
    signature = get_signature(jws, payload)

    # get the request
    request_body = get_request(jws, payload, signature)
    headers = {'Content-type': 'application/jose+json'}


    response = requests.post(challenge_url, data=request_body,
                             headers=headers, verify=ACME_SERVER_CERTIFICATE_PATH)

    data = response.headers
    replace_nonce(data)
    if response.status_code == 200:
        if scope != "cert":
            return response.json()
        else:
            return response
    else:
        response.raise_for_status()


def finalize(domains, finalize_url):

    pem_key = PRIVATE_KEY.export_key(format="PEM")

    key = serialization.load_pem_private_key(pem_key.encode("ASCII"), password=None, backend=default_backend())

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CH"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zurich"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ETH"),
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
    ])).add_extension(

        x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
        critical=False,

    ).sign(key, hashes.SHA256(), default_backend())

    with open(join(dirname(realpath(__file__)), "csr.der"), "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.DER))

    base64_csr = base64.urlsafe_b64encode(csr.public_bytes(encoding=serialization.Encoding.DER)).decode("ASCII").strip("=")

    global KID
    # setting the jws JSON
    jws = get_jws(finalize_url, kid=KID)

    # setting the payload
    payload = {
        "csr": base64_csr
    }

    # signing
    signature = get_signature(jws, payload)

    # get the request
    request_body = get_request(jws, payload, signature)

    headers = {'Content-type': 'application/jose+json'}

    response = requests.post(finalize_url, data=request_body,
                             headers=headers, verify=ACME_SERVER_CERTIFICATE_PATH)

    data = response.headers
    replace_nonce(data)
    if response.status_code == 200:

        return response.json()
    else:
        response.raise_for_status()


def revoke_cert():
    global KID
    # setting the jws JSON
    jws = get_jws(REVOKE_CERT_URL, kid=KID)

    # preparing the payload

    cert_path = join(dirname(realpath(__file__)), '../https_server/sec/cert.pem')

    with open(cert_path, "r") as cert_file:
        cert = cert_file.read()

    certificate = base64.urlsafe_b64encode(x509.load_pem_x509_certificate(bytes(cert, "ASCII"), default_backend()).
                                           public_bytes(encoding=serialization.Encoding.DER)).decode("ASCII").strip("=")

    payload = {
        "certificate": certificate
    }

    # signing
    signature = get_signature(jws, payload)

    # get the request
    request_body = get_request(jws, payload, signature)

    headers = {'Content-type': 'application/jose+json'}

    response = requests.post(REVOKE_CERT_URL, data=request_body,
                             headers=headers, verify=ACME_SERVER_CERTIFICATE_PATH)

    data = response.headers
    replace_nonce(data)
    print(response.text)
    if response.status_code == 200:
        return True
    else:
        response.raise_for_status()

