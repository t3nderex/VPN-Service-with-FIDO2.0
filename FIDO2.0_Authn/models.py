from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, user_json):
        self.user_json = user_json


    def is_authenticated(self):
        return True

    def is_active(self):   
        return True           

    def is_anonymous(self):
        return False          
        
    def get_id(self):
        object_id = self.user_json.get('credential_id')
        return str(object_id)