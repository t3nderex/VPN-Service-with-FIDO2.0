from app import RP_ID, TRUST_ANCHOR_DIR

import binascii
import cbor2
import codecs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, EllipticCurvePublicNumbers, SECP256R1)
from cryptography.hazmat.primitives.asymmetric.padding import (MGF1, PKCS1v15, PSS)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.hashes import SHA256
import hashlib
import json
import os
import six
import struct
import util

from OpenSSL import crypto


class CreateCredentialOptions:
    def __init__(self, username, displayname, attestation_type, authenticator_type):
        self.username =  username
        self.displayname = displayname
        self.attestation_type = attestation_type
        self.authenticator_type = authenticator_type
        self.challenge = ""

    def create_PublicKeyCredentialCreationOptions(self):
        PublicKeyCredentialCreationOptions = {
            'rp' : {
                'name': 'FIDO2.0 VPN',
                'id': 'schfido.com',
                'icon': ''
            },
            'user' : {
                'name': self.username,
                'displayName': self.displayname,
                'id': util.url_safe_base64_encoded_random_bytes()
            },
            'challenge' : util.url_safe_base64_encoded_random_bytes(),
            'pubKeyCredParams': [
                {"type":"public-key","alg":-7},
            ],
            'timeout': 60000,
            'excludeCredentials': [],   # 
            'authenticatorSelection': {
                'requireResidentKey': True,
                'authenticatorAttachment': self.authenticator_type,
                'userVerification': 'required'
            },
            'attestation': self.attestation_type
        }
        if PublicKeyCredentialCreationOptions['authenticatorSelection']['authenticatorAttachment'] == "unspecified":
            del PublicKeyCredentialCreationOptions['authenticatorSelection']['authenticatorAttachment']
        return PublicKeyCredentialCreationOptions
        
class WebAuthnRegistration:
    def __init__(self,
            rp_id,
            origin,
            registration_info,
            challenge,
            trust_anchor_dir,
            trusted_attestation_cert_required=False,
            attestation_permitted=False,
            none_attestation_permitted=False,
            uv_required=False):
        self.rp_id = rp_id
        self.origin = origin 
        self.registration_info = registration_info 
        self.challenge = challenge 
        self.trust_anchor_dir = trust_anchor_dir
        self.trusted_attestation_cert_required = trusted_attestation_cert_required
        self.attestation_permitted = attestation_permitted
        self.none_attestation_permitted = none_attestation_permitted
        self.uv_required = uv_required

    def verify(self):

        clientdataJSON = self.registration_info['response']['clientDataJSON']
        attestationObject = self.registration_info['response']['attestationObject']

        raw_decoded_client_data = util.url_safe_base64_decode_raw(clientdataJSON)
        dict_decoded_client_data = json.loads(util.url_safe_base64_decode(clientdataJSON))
        decoded_attestation_object = util.url_safe_base64_decode_raw(attestationObject)
        cbor_attstation_object = cbor2.loads(decoded_attestation_object)
        cbor_auth_data = cbor_attstation_object['authData'] #authdata
        cbor_stmt = cbor_attstation_object['attStmt']
        cbor_fmt = cbor_attstation_object['fmt']

        # Verify type
        if dict_decoded_client_data['type'] != 'webauthn.create':
            return False

        # Verify challenge
        if dict_decoded_client_data['challenge'] != self.challenge:
            return False
        
        # Verify origin
        if not isinstance(dict_decoded_client_data, dict):
            return False
        else:
            if not dict_decoded_client_data['origin']:
                return False
            if dict_decoded_client_data['origin'] != self.origin:
                return False
        
        # Convert client data to hash
        hash_client_data = hashlib.sha256(raw_decoded_client_data).digest()

        # Verify Authdata size
        if not cbor_auth_data or len(cbor_auth_data) < 37:
            return False

        # Conver rpid to hash and Verify rpid
        hash_rpid = cbor_auth_data[:32]
        if not constant_time.bytes_eq(hash_rpid, hashlib.sha256(bytes(self.rp_id, encoding="utf-8")).digest()):
            return False

        # Verify flag
        flags = struct.unpack('!B', cbor_auth_data[32:33])[0]
        if(flags & 1 << 0) != 0x01:
            return False
        
        # Veirfy user verify
        if (self.uv_required and (flags & 1 << 2 != 0x04)):
            return False

        # Verify fmt
        if not isinstance(cbor_fmt, six.string_types):
            return False
        
        #step14, 734행

        attestation_data = cbor_auth_data[37:]
        aaguid = attestation_data[:16]
        len_credential_id = struct.unpack('!H', attestation_data[16:18])[0]
        cred_id = attestation_data[18:18 + len_credential_id]
        credential_public_key = attestation_data[18 + len_credential_id:]

        
        if cbor_fmt == "none":
            if not self.none_attestation_permitted:
                return False

        attestation_type = "None"

            
        trust_path = []
        
        #step 16 pass
        # attestation_type, trust_path, credential_public_key, cred_id
        
        if TRUST_ANCHOR_DIR == "attestation_root":
            trust_anchor_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR)
        else:
            trust_anchor_dir = TRUST_ANCHOR_DIR
        
        trust_anchor = []
        
        if os.path.isdir(trust_anchor_dir):
            for trust_anchor_name in os.listdir(trust_anchor_dir):
                trust_anchor_path = os.path.join(trust_anchor_dir, trust_anchor_name)
                if os.path.isfile(trust_anchor_path):
                    with open(trust_anchor_path, 'rb') as f:
                        pem_data = f.read().rstrip()
                        try:
                            pem = crypto.load_certificate(crypto.FILETYPE_PEM, pem_data)
                            trust_anchor.append(pem)
                        except Exception:
                            pass
        
        if not trust_anchor and self.trusted_attestation_cert_required:
            return False

        # Get sign count
        sign_count = struct.unpack('!I', cbor_auth_data[33:37])[0]
        return {
            'credential_id': util.url_safe_base64_encode(cred_id),
            'origin': self.origin,
            'public_key': util.url_safe_base64_encode(credential_public_key),
            'rp_id': self.rp_id,
            'sign_count': sign_count
            }

class WebauthAssertion:
    def __init__(self,
                credential,
                assertion_response,
                challenge,
                origin,
                allow_credentials=None,
                uv_required=False):
        self.credential = credential
        self.assertion_response = assertion_response
        self.challenge = challenge
        self.origin = origin
        self.allow_credentials = allow_credentials
        self.uv_required = uv_required

    def verify(self):
        # Verify Credential ID
        credential_id = self.assertion_response['id']
        if self.allow_credentials:
            if credential_id not in self.allow_credentials:
                return False

        # Verify username
        if not self.credential['username']:
            return False

        if not isinstance(self.credential['credential_id'], six.string_types):
            return False

        # Veirfy public key
        if not self.credential['public_key']:
            return False
        
        credential_public_key = self.credential['public_key']
        cbor_public_key = cbor2.loads(util.url_safe_base64_decode_raw(self.credential['public_key']))
        
        if 3 not in cbor_public_key:
            return False

        alg = cbor_public_key[3]
        if alg == -7:
            X_KEY = -2
            Y_KEY = -3
            required_keys = {3, X_KEY, Y_KEY}
            if not set(cbor_public_key.keys()).issuperset(required_keys):
                return False
            if len(bytes(cbor_public_key[X_KEY])) != 32:
                return False
                
            x = int(codecs.encode(cbor_public_key[X_KEY], 'hex'), 16)
            if len(bytes(cbor_public_key[Y_KEY])) != 32:
                return False
            y = int(codecs.encode(cbor_public_key[Y_KEY], 'hex'), 16)
            public_key_alg = alg
            user_pubkey = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key(backend=default_backend())
        elif alg in (-37, -257):
            E_KEY = -2
            N_KEY = -1
            required_keys = {3, E_KEY, N_KEY}
            if not set(cbor_public_key.keys()).issuperset(required_keys):
                return False

            if len(cbor_public_key[E_KEY]) != 3 or len(cbor_public_key[N_KEY]) != 256:
                return False
            e = int(codecs.encode(cbor_public_key[E_KEY], 'hex'), 16)
            n = int(codecs.encode(cbor_public_key[N_KEY], 'hex'), 16)

            public_key_alg = alg
            user_pubkey = RSAPublicNumbers(e, n).public_key(backend=default_backend())

        else:
            return False


        # step 4

        clientdata = self.assertion_response['clientData']
        authdata = self.assertion_response['authData']
        decoded_authdata = util.url_safe_base64_decode_raw(authdata)    
        signature = binascii.unhexlify(self.assertion_response['signature'])
        decoded_clientdata = util.url_safe_base64_decode_raw(clientdata)
        json_clientdata = json.loads(decoded_clientdata)

        received_type = json_clientdata['type']

        #step 7
        if not received_type == 'webauthn.get':
            return False

        #step8
        received_challnge = json_clientdata['challenge']
        if not received_challnge == self.challenge:
            return False

        # Verify Origin
        if not isinstance(json_clientdata, dict):
            return False

        client_data_origin = json_clientdata['origin']
        if not client_data_origin:
            return False
        if client_data_origin != self.origin:
            return False

        # Verify authData
        if not isinstance(decoded_authdata, six.binary_type):
            return False
        
        auth_data_rpid_hash = decoded_authdata[:32]
        rp_id_hash = hashlib.sha256(bytes(self.credential['rp_id'], "utf-8")).digest()
        if not constant_time.bytes_eq(auth_data_rpid_hash, rp_id_hash):
            return False

        # Verify flags
        flags = struct.unpack('!B', decoded_authdata[32:33])[0]
        if flags & 1 << 0 != 0x01:
            return False
        if self.uv_required and (flags & 1 << 2) != 0x04:
            return False
        
        
        # Verify Client Data
        if not isinstance(decoded_clientdata, six.binary_type):
            return False
            
        client_data_hash = hashlib.sha256(decoded_clientdata).digest()

        # step 16 
        bytes_to_verify = b''.join([decoded_authdata, client_data_hash])
        
        # Verify Signature
        if public_key_alg == -7:
            user_pubkey.verify(signature, bytes_to_verify, ECDSA(SHA256()))
        elif public_key_alg == -257:
            user_pubkey.verify(signature, bytes_to_verify, PKCS1v15(), SHA256())
        elif public_key_alg == -37:
            padding = PSS(mgf=MGF1(SHA256()), salt_length=32)
            user_pubkey.verify(signature, bytes_to_verify, padding, SHA256())
        else:
            return False
        # Verify Sign Count
        sc = decoded_authdata[33:37]
        sign_count = struct.unpack('!I', sc)[0]

        if sign_count == 0 and self.credential['sign_count'] == 0:
            return 0
        
        if not sign_count:
            return False

        if (isinstance(self.credential['sign_count'], int) and self.credential['sign_count'] < 0) or not isinstance(self.credential['sign_count'], int):
            return False
        
        if sign_count <= self.credential['sign_count']:
            return False

        return sign_count