import grpc

import secretsharing_pb2 as s_shr_pb
import secretsharing_pb2_grpc as s_shr_grpc

import jwt
from jwt.algorithms import RSAAlgorithm

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import requests
import json

def reformat_pem_key(key):
    formated = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % key
    print(formated)
    return formated
    
def check_jwt_signature(jwt_token):
    url = 'https://aas.us.attest.azure.net/certs'
    response = requests.get(url).json()
    keys = response['keys']
    certs = dict()
    for jwk in keys:
        kid = jwk['kid']
        certs[kid] = jwk['x5c']
    kid = jwt.get_unverified_header(jwt_token)['kid']

    pem_data = reformat_pem_key(certs[kid][0])
    key_ascii = pem_data.encode('ascii')
    cert = x509.load_pem_x509_certificate(key_ascii, default_backend())
    public_key = cert.public_key()

    payload = jwt.decode(jwt_token, key=public_key, algorithms=['RS256'])
    print(json.dumps(payload, indent=2))

def run():
    with grpc.insecure_channel(target='localhost:5000',
                               options=[('grpc.enable_retries', 0),
                                        ('grpc.keepalive_timeout_ms', 100)
                                       ]) as channel:
        stub = s_shr_grpc.SecretSharingStub(channel)
        response = stub.GetAttestation(
            s_shr_pb.AttestationRequest(cmd=s_shr_pb.CommandRequest.ATTESTATION))
    if response.ok:
        print("Get Attestation response: %s" % response.msg)
        check_jwt_signature(response.token)
    else:
        print("Get Attestation failed with message: %s" % response.msg)

if __name__ == '__main__':
    run()
