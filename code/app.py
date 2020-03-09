from flask import Flask
from flask_restful import Api
from flask_jwt_extended import JWTManager

from db import db
from resources.user import UserRegister,User,UserLogin,UserLogout,TokenRefresh
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blacklist import BLACKLIST

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True # default olarak false
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access','refresh']
app.secret_key = 'jose' #app.config['JWT_SECRET_KEY']
api = Api(app)


@app.before_first_request
def create_tables():
    db.create_all()


jwt = JWTManager(app)  # not creating the /auth endpoint ** bu sefer link verdik haberdar olucak böylede jwt manager uygulamadan
#authanticate ve idendtiy fonksiyonlarınıda kullanmcaz

@jwt.user_claims_loader
def add_claims_to_jwt(identity):#burada identitiy parametresi access token oluştururken identity e geçtiğimiz parametreyi alır
    if identity == 1: #Instead of hard-coding , you should read from a config file or db
        return {'is_admin':True}
    return {'is_admin':False}

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token): # tam anlamadım
    return decrypted_token['jti'] in BLACKLIST


@jwt.expired_token_loader#bunun sayesinde access token süresi geçince bu fonksiyonu çalıştırabiliyoruz
def expired_token_callback():#flask manager sayesinde 
    return jsonify(
        {
            'descripion':"The token has expired.",
            'error':"token_expired"
        }
    )

@jwt.invalid_token_loader #gelen jwt gerçek değilse devreye girer.Örneğin auh header a rastgele string yazıp çalıştırmayı denersek
def invalid_token_callback(error):
    return jsonify(
        {
            'descripion':"Signature verification failed.",
            'error':"invalid_token"
        }
    )
#githubdan alındı https://github.com/tecladocode/flask-jwt-extended-section-lectures/blob/master/9_customizing_callbacks_and_responses/end/app.py
@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'description': 'Request does not contain an access token.',
        'error': 'authorization_required'
    }), 401


@jwt.needs_fresh_token_loader
def token_not_fresh_callback():
    return jsonify({
        'description': 'The token is not fresh.',
        'error': 'fresh_token_required'
    }), 401


@jwt.revoked_token_loader
def revoked_token_callback():
    return jsonify({
        'description': 'The token has been revoked.',
        'error': 'token_revoked'
    }), 401

api.add_resource(Store, '/store/<string:name>')
api.add_resource(StoreList, '/stores')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(UserRegister, '/register')
api.add_resource(User,'/user/<int:user_id>')
api.add_resource(UserLogin,'/login')
api.add_resource(UserLogout,'/logout')
api.add_resource(TokenRefresh,'/refresh')

if __name__ == '__main__':
    db.init_app(app)
    app.run(port=5000, debug=True)
