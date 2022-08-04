function UrlSafeBase64Decode(str) {
    let base64EncodedString = str;
    base64EncodedString = base64EncodedString.replace(/[-_]/g, match => ({
        '-': '+',
        '_': '/'
    } [match]));
    let base64DecodedString = atob(base64EncodedString);
    let base64DecodedArray = new Uint8Array(base64DecodedString.length);
    for (let i = 0; i < base64DecodedString.length; i++) {
        base64DecodedArray[i] = base64DecodedString.charCodeAt(i);
    }
    return base64DecodedArray;
}

function UrlSafeBase64Decode32(str) {
    let base64EncodedString = str;
    base64EncodedString = base64EncodedString.replace(/[-_]/g, match => ({
        '-': '+',
        '_': '/'
    } [match]));
    let base64DecodedString = atob(base64EncodedString);
    let base64DecodedArray = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        base64DecodedArray[i] = base64DecodedString.charCodeAt(i);
    }
    return base64DecodedArray;
}

function UrlSafeBase64Encode(buf) {
    let plainBinary = '';
    let plainArray = new Uint8Array(buf);
    for (let i = 0; i < plainArray.length; i++) {
        plainBinary += String.fromCharCode(plainArray[i]);
    }
    let base64EncodedString = window.btoa(plainBinary).replace(/[+/=]/g, match => ({
        '+': '-',
        '/': '_',
        '=': ''
    } [match]));
    return base64EncodedString;
}

function hexEncode(buf) {
    return Array.from(buf)
        .map(function (char) {
            return ("0" + char.toString(16)).substr(-2);
        })
        .join("");
}

function createPublicKeyCredential() {
    let credential;
    let formData = new FormData(document.getElementById('inputForm'));
    const object = {};
    let PublicKeyCredentialOptions;
    formData.forEach((value, key) => object[key] = value);
    if (object["username"] == "" || object["displayname"] == "") {
        alert("Value is empty!");
        window.location.reload();
    }
    const json = JSON.stringify(object);
    fetch("/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: json,
            dataType: "json"
        }).then((response) => response.json())
        .then((data) => {;
            if (data['error'] == 'Already Exist Username') {
                alert('Already Exist Username')
                throw new Error('Already Exist Username')
            }
            PublicKeyCredentialOptions = data;
            PublicKeyCredentialOptions.challenge = UrlSafeBase64Decode(PublicKeyCredentialOptions['challenge'])
            PublicKeyCredentialOptions.user.id = UrlSafeBase64Decode(PublicKeyCredentialOptions['user']['id'])
            return credential = navigator.credentials.create({
                publicKey: PublicKeyCredentialOptions
            });
        })
        .then((credential) => {
            let cred = {};
            cred.id = credential.id;
            cred.rawId = UrlSafeBase64Encode(credential.rawId);
            cred.type = credential.type;
            if (credential.response) {
                let clientDataJSON = UrlSafeBase64Encode(credential.response.clientDataJSON);
                let attestationObject = UrlSafeBase64Encode(credential.response.attestationObject);
                cred.response = {
                    clientDataJSON,
                    attestationObject
                };
                return cred;
            }
        })
        .then((cred) => {
            cred = JSON.stringify(cred);
            fetch("/register2", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: cred
            }).then((response) => alert("Register Succeded!"))
        })
        .catch((error) => alert("Register Failed!"));
}

function login() {
    let assertion;
    let formData = new FormData(document.getElementById('inputForm'));
    const object = {};
    formData.forEach((value, key) => object[key] = value);
    if (object["username"] == "" || object["displayname"] == "") {
        alert("Value is not empty!");
        window.location.reload();
    }
    const json = JSON.stringify(object);
    fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: json,
            dataType: "json"
        }).then((response) => response.json())
        .then((data) => {
            publicKeyRequestOptions = data
            let {
                challenge,
                allowCredentials
            } = publicKeyRequestOptions;
            challenge = UrlSafeBase64Decode(challenge);
            allowCredentials = allowCredentials[0]['id'];
            allowCredentials = UrlSafeBase64Decode(allowCredentials);
            publicKeyRequestOptions['challenge'] = challenge;
            publicKeyRequestOptions['allowCredentials'][0]['id'] = allowCredentials;
            return publicKeyRequestOptions
        }).then((publicKeyRequestOptions) => {
            assertion = navigator.credentials.get({
                publicKey: publicKeyRequestOptions
            });
            return assertion;
        }).then((assertion) => {
            console.log(assertion);
            const authData = new Uint8Array(assertion.response.authenticatorData);
            const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
            const rawId = new Uint8Array(assertion.rawId);
            const signature = new Uint8Array(assertion.response.signature);
            const userHandle = new Uint8Array(assertion.response.userHandle);
            return_assertion = {
                id: assertion.id,
                rawId: UrlSafeBase64Encode(rawId),
                type: assertion.type,
                userHandle: userHandle,
                authData: UrlSafeBase64Encode(authData),
                clientData: UrlSafeBase64Encode(clientDataJSON),
                signature: hexEncode(signature)
            }
            fetch("/login2", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(return_assertion),
                dataType: "json"
            }).then(response => response.json())
            .then((data) => {
                if (data['status'] == 'true') {
                    window.location.reload();
                } else if (data['status'] == 'false'){
                    alert("Login Failed");
                }  
            });                                                                                                                 
        })
        .catch((error) => alert("Login Failed!"));
}; 


// const formData = new FormData();
// Object.entries(assertionDataForServer).forEach(([key, value]) => {
//     formData.set(key, value);