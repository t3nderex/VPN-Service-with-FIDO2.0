import base64
import secrets

USERNAME_MAX_LENGTH =32

def validater_userid(username):
    """
        userid의 유효성을 검사하는 함수;
        세 조건중 하나라도 만족하면 정상적인 id가 아님
    """
    
    if len(username) > 32:              # 32글자 제한
        return False
    
    if not isinstance(username, str):   # 문자열로 제한
        return False

    if not username.isalnum():          # ASCII 코드로 제한
        return False                      

    return True # 세 조건 모두 만족하지 못하면 정상적인 id값으로 판단

def url_safe_base64_decode(str):
        padding = (-len(str) % 4)
        str += '=' * padding
        return base64.urlsafe_b64decode(str).decode('utf-8')

def url_safe_base64_decode_raw(str):
        padding = (-len(str) % 4)
        str += '=' * padding
        return base64.urlsafe_b64decode(str)

def url_safe_base64_encode(bytes):
        return base64.urlsafe_b64encode(bytes).decode('utf-8').rstrip('=')

def url_safe_base64_encoded_random_bytes():
    random_bytes = secrets.token_bytes(32)
    return url_safe_base64_encode(random_bytes)