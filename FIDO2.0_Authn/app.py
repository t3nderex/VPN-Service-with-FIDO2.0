from models import User
from socket_server import socket_server

import os
import secrets
import server
import ssl
from threading import Thread
import time
import util

from pymongo import MongoClient
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_login import AnonymousUserMixin, LoginManager, login_required, login_user, logout_user


class AnonymousUserMixin(object):
    def __init__(self) -> None:
        super().__init__()
        self.authenticate_status = ""
        self.active_status = ""       
    

    @property
    def is_authenticated(self):
        return self.authenticate_status
    

    @property
    def is_active(self):
        return self.active_status


    @property
    def is_anonymous(self):
        return False
        
        
    def get_id(self):
        return 
        
RP_ID = 'schfido.com'
RP_NAME = 'fido-server'
ORIGIN ='https://schfido.com:44334'
TRUST_ANCHOR_DIR = 'attestation_root'

client = MongoClient('mongodb://localhost:27017/')
db = client['fido-server']          # Create new Database
collection = db['Credential']       # Create new Collection

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)

login_manager = LoginManager()
login_manager.init_app(app)

user = AnonymousUserMixin()
user.authenticate_status = False
user.active_status = False

@login_manager.user_loader
def load_user(user_credential_id):
    return AnonymousUserMixin(user_credential_id)

# 인덱스 페이지
@app.route('/')
def index():
    try:
        if session['username'] is not None and session['id'] is not None:
            return render_template('index.html', username=session['username'])
    except:
        return render_template('index.html')

# 로그아웃시 인덱스 페이지로 리다이렉션
@app.route('/register', methods=['POST'])
def register():
    global credentialinfo
    
    request_data = request.get_json()
    if util.validater_userid(request_data['username']) == False:
        print(f"{session['username']} : Invailid User Input")
        return jsonify(error="ID is not valid."), 403
    session.pop('id', None)
    session.pop('challenge', None)
    session.pop('username', None)
    session.pop('displayname', None)
    fido_server = server.CreateCredentialOptions(request_data['username'], request_data['displayname'], request_data['attestation-type'], request_data['authenticator-type'])

    PublicKeyCredentialCreationOptions = fido_server.create_PublicKeyCredentialCreationOptions()
    credentialinfo = PublicKeyCredentialCreationOptions
    session['id'] = PublicKeyCredentialCreationOptions['user']['id']
    session['challenge'] = PublicKeyCredentialCreationOptions['challenge']
    session['username'] = request_data['username']
    session['displayname'] = request_data['displayname']

    if collection.find_one({'username': session['username']}):
        print(f"{session['username']} : Attempt Duplicate Registration")
        return jsonify(error="Already Exist Username"), 403
    return jsonify(PublicKeyCredentialCreationOptions)

@app.route('/register2', methods=['POST'])
def register2():
    registration_info = request.get_json()
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), TRUST_ANCHOR_DIR) 
    
    webauthn_registration = server.WebAuthnRegistration(
        RP_ID,
        ORIGIN,
        registration_info,
        session['challenge'],
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
    )
    
    credential = webauthn_registration.verify()
    if credential is False:
        print(f"{session['username']} : Registraion Failed")
        return jsonify({'status':'false'})

    # stroe in db
    credential['id'] = session['id']
    credential['username'] = session['username']
    credential['displayname'] = session['displayname']
    collection.insert_one(credential)

    print(f"{session['username']} : Registraion Succeed")
    session.pop('id', None)
    session.pop('challenge', None)
    session.pop('username', None)
    session.pop('displayname', None)
    return jsonify({'status':'true'})


@app.route('/login', methods=['POST'])
def login():
    session.pop('id', None)
    session.pop('challenge', None)
    session.pop('username', None)
    session.pop('displayname', None)
    assertion_info = request.get_json()
    username = assertion_info['username']
    search_status = False
    
    #id 유효성 검사
    db_data = collection.find()
    for credential in db_data:
        if credential['username'] == username:
            print(f"{credential['username']} : Attempt Normal Registration")
            db_credential = credential
            search_status = True
            break
    if search_status == False:
        print(f"{credential['username']} : Attempt Abnormal Registration")
        return jsonify({"status":"False"})
    
    session.pop('challenge', None)
    challenge = util.url_safe_base64_encoded_random_bytes()
    session['challenge'] = challenge

    credentials = []
    # for uuser in users:
    credentials.append({
        'type': 'public-key',
        'id': db_credential['credential_id'],
    })

    PublicKeyCredentialRequstOptions = {
        'challenge': challenge,
        'allowCredentials': credentials,
        'rpId': db_credential['rp_id'],
        'timeout': 600000,
        'userVerification': 'required'
    }
    return jsonify(PublicKeyCredentialRequstOptions)

@app.route('/login2', methods=['POST'])
def login2():
    assertion_info = request.get_json()
    challenge = session.get("challenge")
    credential_id = assertion_info['id']
    
    db_credential = collection.find_one({'credential_id': credential_id})
    if not db_credential:
        return jsonify({"status":"false"})
    
    if not db_credential['credential_id']:
        return jsonify({"status":"false"})
    
    if not db_credential['rp_id']:
        return jsonify({"status":"false"})
    
    user_assertion = server.WebauthAssertion(
                        db_credential,
                        assertion_info,
                        challenge,
                        ORIGIN,
                        None,
                        True
                    )
    sign_count = user_assertion.verify()
    if sign_count != False:
        collection.update_one({'credential_id': credential_id}, {'$set':{"sign_count":sign_count}})
        db_credential = collection.find_one({'credential_id': credential_id})
        session['username'] = db_credential['username']
        session['id'] = db_credential['id']
        print(f"{session['username']} : Login Succeed")

        user.authenticate_status = True
        user.active_status = True
        login_user(user)
        socket = socket_server("192.168.0.4", 44335)
        socket.message = b"Succeed"
        thread = Thread(target=socket.start)
        thread.daemon = True
        thread.start()
        return jsonify({"status":"true"})
    else:
        print(f"{session['username']} : Login Failed")

        socket = socket_server("192.168.0.4", 44335)
        socket.message = b"Failed"
        thread = Thread(target=socket.start)
        thread.daemon = True
        thread.start()
        jsonify({"status":"false"})
    
@app.route('/logout')
def logout():
    print(f"{session['username']} : Logout")
    session.clear()
    return redirect(url_for('index'))
    


if __name__ == '__main__':
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.load_cert_chain(certfile='./attestation_root/private.crt', keyfile='./attestation_root/private.key', password='schcsrc')
    app.config['SECRET_KEY'] = 'f48jnu9ksrnuwnj0'
    app.run(host="0.0.0.0", port=443, ssl_context=ssl_context, debug=True)



