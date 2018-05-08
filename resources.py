from flask import jsonify
from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

from models import UserModel, RevokedTokenModel, LeavesModel

parser = reqparse.RequestParser()
parser.add_argument('email', help='This field cannot be blank', required=True)
parser.add_argument('password', help='This field cannot be blank', required=True)
parser.add_argument('role', help='This field cannot be blank', required=True)

login_parser = reqparse.RequestParser()
login_parser.add_argument('email', help='This field cannot be blank', required=True)
login_parser.add_argument('password', help='This field cannot be blank', required=True)

leave_parser = reqparse.RequestParser()
leave_parser.add_argument('leave_type', help='This field cannot be blank', required=True)
leave_parser.add_argument('description', help='This field cannot be blank', required=True)
leave_parser.add_argument('employee_id', help='This field cannot be blank', required=True)
leave_parser.add_argument('from_date', help='This field cannot be blank', required=True)
leave_parser.add_argument('to_date', help='This field cannot be blank', required=True)
leave_parser.add_argument('num_of_days', help='This field cannot be blank', required=True)
leave_parser.add_argument('status', help='This field cannot be blank', required=True)


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_email(data['email']):
            return {'message': 'User {} already exists'.format(data['email'])}, 400

        new_user = UserModel(
            email=data['email'],
            password=UserModel.generate_hash(data['password']),
            role=data['role']
        )
        try:
            new_user.save_to_db()
            return {
                'message': 'User {} is created'.format(data['email'])
            }
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogin(Resource):
    def post(self):
        data = login_parser.parse_args()
        current_user = UserModel.find_by_email(data['email'])

        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['email'])}, 404

        if UserModel.verify_hash(data['password'], current_user.password):
            access_token = create_access_token(identity=data['email'])
            refresh_token = create_refresh_token(identity=data['email'])
            return jsonify({
                'id': format(current_user.id),
                'email': format(current_user.email),
                'access_token': access_token,
                'refresh_token': refresh_token
            })
        else:
            return {'message': 'Wrong credentials'}, 401


class UserLogoutAccess(Resource):
    @jwt_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Access token has been revoked'}, 200
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            revoked_token = RevokedTokenModel(jti=jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class TokenRefresh(Resource):
    @jwt_refresh_token_required
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return {'access_token': access_token}, 200


class AllUsers(Resource):
    def get(self):
        return UserModel.return_all()


class AddLeave(Resource):
    @jwt_required
    def post(self):
        data = leave_parser.parse_args()
        new_leave = LeavesModel(
            leave_type=data['leave_type'],
            description=data['description'],
            employee_id=data['employee_id'],
            from_date=data['from_date'],
            to_date=data['to_date'],
            num_of_days=data['num_of_days'],
            status=data['status']
        )
        try:
            new_leave.save_to_db()
            return {'message': 'Away created successfully'}
        except:
            return {'message': 'Something went wrong'}, 500


class getAllLeaves(Resource):
    @jwt_required
    def get(self):
        return LeavesModel.get_all_leaves()


class GetLeavesByEmployee(Resource):
    @jwt_required
    def get(self, pk):
        return LeavesModel.get_applied_leaves(pk)
