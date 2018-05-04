from flask import jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

from models import UserModel, RevokedTokenModel
from run import app

parser = reqparse.RequestParser()
parser.add_argument('email', help='This field cannot be blank', required=True)
parser.add_argument('password', help='This field cannot be blank', required=True)
# parser.add_argument('first_name', help='This field cannot be blank', required=False)
# parser.add_argument('last_name', help='This field cannot be blank', required=False)
# parser.add_argument('gender', help='This field cannot be blank', required=False)
# parser.add_argument('skills', help='This field cannot be blank', required=False)
# parser.add_argument('client', help='This field cannot be blank', required=False)
# parser.add_argument('address', help='This field cannot be blank', required=False)
# parser.add_argument('imageUrl', help='This field cannot be blank', required=False)
# parser.add_argument('joining_date', help='This field cannot be blank', required=False)
# parser.add_argument('dob', help='This field cannot be blank', required=False)
# parser.add_argument('role', help='This field cannot be blank', required=True)

login_parser = reqparse.RequestParser()
login_parser.add_argument('email', help='This field cannot be blank', required=True)
login_parser.add_argument('password', help='This field cannot be blank', required=True)


@app.route('/api/v1/registration', methods=['POST'])
def registration():
    data = parser.parse_args()

    if UserModel.find_by_email(data['email']):
        return {'message': 'User {} already exists'.format(data['email'])}

    new_user = UserModel(
        email=data['email'],
        password=UserModel.generate_hash(data['password'])
        # first_name=data['first_name'],
        # last_name=data['last_name'],
        # gender=data['gender'],
        # skills=data['skills'],
        # client=data['client'],
        # address=data['address'],
        # imageUrl=data['imageUrl'],
        # joining_date=data['joining_date'],
        # dob=data['dob'],
        # role=data['role']
    )
    try:
        new_user.save_to_db()
        return {
            'message': 'User {} is created'.format(data['email']),
        }
    except:
        return {'message': 'Something went wrong'}, 500


@app.route('/api/v1/login', methods=['POST'])
def login_auth():
    data = login_parser.parse_args()
    current_user = UserModel.find_by_email(data['email'])

    if not current_user:
        return {'message': 'User {} doesn\'t exist'.format(data['email'])}

    if UserModel.verify_hash(data['password'], current_user.password):
        access_token = create_access_token(identity=data['email'])
        refresh_token = create_refresh_token(identity=data['email'])
        return jsonify({
            'id': format(current_user.id),
            'email': format(current_user.email),
            # 'role': format(current_user.role),
            'access_token': access_token,
            'refresh_token': refresh_token
        })
    else:
        return {'message': 'Wrong credentials'}


@app.route('/api/v1/logout/access', methods=['POST'])
@jwt_required
def logout_access():
    jti = get_raw_jwt()['jti']
    try:
        revoked_token = RevokedTokenModel(jti=jti)
        revoked_token.add()
        return {'message': 'Access token has been revoked'}
    except:
        return {'message': 'Something went wrong'}, 500


@app.route('/api/v1/logout/refresh', methods=['POST'])
@jwt_refresh_token_required
def revoke_token():
    jti = get_raw_jwt()['jti']
    try:
        revoked_token = RevokedTokenModel(jti=jti)
        revoked_token.add()
        return {'message': 'Refresh token has been revoked'}
    except:
        return {'message': 'Something went wrong'}, 500


@app.route('/api/v1/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def token_refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return {'access_token': access_token}


@app.route('/api/v1/users', methods=['GET'])
@jwt_required
def getUsers():
    return UserModel.return_all()


@app.route('/api/v1/users/', methods=['DELETE'])
@jwt_required
def deleteUsers():
    return UserModel.delete_all()


class SecretResource(Resource):
    @jwt_required
    def get(self):
        return {
            'answer': 42
        }
