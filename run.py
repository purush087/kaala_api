import os

from flask import Flask
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}}, supports_credentials=True)
api = Api(app)
app.config.from_object(os.environ['APP_SETTINGS'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['CORS_HEADERS'] = 'Content-Type'
jwt = JWTManager(app)

db = SQLAlchemy(app)
print(os.environ['APP_SETTINGS'])

import views, models, resources

@app.before_first_request
def create_tables():
    db.create_all()


@app.after_request
def apply_caching(response):
    response.headers["Content-Type"] = "application/x-www-form-urlencoded"
    return response


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)


api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.AddLeave, '/leaves')
api.add_resource(resources.GetAllLeaves, '/leaves/all')
api.add_resource(resources.GetLeavesByEmployee, '/leaves/<pk>')
api.add_resource(resources.EditLeaveByEmployee, '/leaves/<pk>')
api.add_resource(resources.GetLeaveTypes, '/leaves/getTypes')
api.add_resource(resources.AddLeaveTypes, '/leaves/addTypes')
api.add_resource(resources.EditLeaveTypes, '/leaves/editTypes/<pk>')
api.add_resource(resources.DeleteLeaveTypes, '/leaves/deleteTypes/<int:id>')