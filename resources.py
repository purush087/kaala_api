import random
import string

from flask import jsonify
import smtplib
from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)

from models import UserModel, RevokedTokenModel, LeavesModel, LeaveTypesModel

parser = reqparse.RequestParser()
parser.add_argument('email', help='This field cannot be blank', required=True)
parser.add_argument('emp_id', help='This field cannot be blank', required=True)
parser.add_argument('password', help='This field cannot be blank', required=True)
parser.add_argument('role', help='This field cannot be blank', required=True)

login_parser = reqparse.RequestParser()
login_parser.add_argument('email', help='This field cannot be blank', required=True)
login_parser.add_argument('password', help='This field cannot be blank', required=True)

leaveType_parser = reqparse.RequestParser()
leaveType_parser.add_argument('leave_type', help='manadatory field', required=True)
leaveType_parser.add_argument('description', help='Optional field')
leaveType_parser.add_argument('num_of_days', help='manadatory field', required=True)
leaveType_parser.add_argument('validity', help='manadatory field', required=True)
leaveType_parser.add_argument('carry_forward', help='manadatory field', required=True)

leave_parser = reqparse.RequestParser()
leave_parser.add_argument('leave_type', help='This field cannot be blank', required=True)
leave_parser.add_argument('description', help='This field cannot be blank', required=True)
leave_parser.add_argument('from_date', help='This field cannot be blank', required=True)
leave_parser.add_argument('to_date', help='This field cannot be blank', required=True)
leave_parser.add_argument('num_of_days', help='This field cannot be blank', required=True)
leave_parser.add_argument('status', help='This field cannot be blank', required=True)


class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()

        if UserModel.find_by_email(data['email']):
            return {'message': 'User {} already exists'.format(data['email'])}, 400
        random_char = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])
        content = "your password for kaala app is " + random_char
        mail=""
        password=""
        self.send_email(mail, password, data['email'], content)
        new_user = UserModel(
            emp_id=data['emp_id'],
            email=data['email'],
            password=UserModel.generate_hash(random_char),
            role=data['role']
        )

        try:
            new_user.save_to_db()
            return {
                'message': 'User {} is created'.format(data['email']),
                'password': random_char
            }
        except:
            return {'message': 'Something went wrong'}, 500

    def send_email(self, mail, password, to, content):
        mail = smtplib.SMTP('smtp.gmail.com', 587)
        mail.starttls()
        mail.login(mail, password)
        mail.sendmail(mail, to, content)
        mail.close()


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
        current_user = UserModel.find_by_email(get_jwt_identity())
        new_leave = LeavesModel(
            leave_type=data['leave_type'],
            description=data['description'],
            employee_id=current_user.id,
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


class GetAllLeaves(Resource):
    @jwt_required
    def get(self):
        return LeavesModel.get_all_leaves(), 200


class GetLeavesByEmployee(Resource):
    @jwt_required
    def get(self, pk):
        return LeavesModel.get_applied_leaves(pk), 200


class GetLeaveTypes(Resource):
    @jwt_required
    def get(self):
        return LeaveTypesModel.get_leave_types()


class EditLeaveByEmployee(Resource):
    @jwt_required
    def put(self, pk):
        data = leave_parser.parse_args()
        prev_leave = LeavesModel.get_particular_leave(pk)
        prev_leave.leave_type = data['leave_type']
        prev_leave.description = data['description']
        prev_leave.from_date = data['from_date']
        prev_leave.to_date = data['to_date']
        prev_leave.num_of_days = data['num_of_days']
        prev_leave.status = data['status']

        try:
            prev_leave.update_to_db()
            return {'message': 'Away updated successfully'}
        except:
            return {'message': 'Something went wrong'}, 500


class AddLeaveTypes(Resource):
    @jwt_required
    def post(self):
        data = leaveType_parser.parse_args()
        current_user = UserModel.find_by_email(get_jwt_identity())
        is_current_user_admin = UserModel.find_role(current_user.id)

        if not is_current_user_admin:
            return {'message': 'User {} is not admin'.format(current_user.email)}, 400

        new_leave_type = LeaveTypesModel(
            leave_type=data['leave_type'],
            description=data['description'],
            num_of_days=data['num_of_days'],
            validity=data['validity'],
            carry_forward=data['carry_forward'],
            employee_id=current_user.id
        )
        try:
            new_leave_type.save_to_db()
            return {'message': 'Leave type added successfully'}
        except:
            return {'message': 'Unable to add data'}, 500


class EditLeaveTypes(Resource):
    @jwt_required
    def put(self, pk):
        data = leaveType_parser.parse_args()
        current_user = UserModel.find_by_email(get_jwt_identity())
        is_current_user_admin = UserModel.find_role(current_user.id)

        if not is_current_user_admin:
            return {'message': 'User {} is not admin'.format(current_user.email)}, 400

        prev_leave_type = LeaveTypesModel.get_particular_leaveType(pk)
        prev_leave_type.leave_type = data['leave_type']
        prev_leave_type.description = data['description']
        prev_leave_type.num_of_days = data['num_of_days']
        prev_leave_type.validity = data['validity']
        prev_leave_type.carry_forward = data['carry_forward']
        prev_leave_type.employee_id = current_user.id

        try:
            prev_leave_type.update_to_db()
            return {'message': 'Leave type updated successfully'}

        except:
            return {'message': 'Something went wrong'}, 500


class DeleteLeaveTypes(Resource):
    @jwt_required
    def delete(self, id):
        current_user = UserModel.find_by_email(get_jwt_identity())
        is_current_user_admin = UserModel.find_role(current_user.id)

        if not is_current_user_admin:
            return {'message': 'User {} is not admin'.format(current_user.email)}, 400

        try:
            LeaveTypesModel.delete_leaveType(id)
            return {'message': 'Leave type deleted successfully'}
        except:
            return {'message': 'Something went wrong'}, 500
