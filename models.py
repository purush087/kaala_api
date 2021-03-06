import datetime

from flask import jsonify

from run import db
from passlib.hash import pbkdf2_sha256 as sha256


class UserModel(db.Model):
    __tablename__ = 'users'
    email = db.Column(db.String(120), unique=True, nullable=False)
    emp_id = db.Column(db.Integer, primary_key=True, unique=True)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.Integer, nullable=False)
    last_sign_in_at = db.Column(db.DateTime)
    last_sign_in_ip = db.Column(db.String(255))
    current_sign_in_at = db.Column(db.DateTime)
    current_sign_in_ip = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now)
    user_details = db.relationship('UserProfile', uselist=False, backref='users')
    leaves = db.relationship('LeavesModel', backref='users')

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def find_role(cls, id):
        employee = cls.query.filter_by(id=id).first()
        return True if employee.__getattribute__('role') == 'admin' else False

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'email': x.email,
                'role': x.role,
                'first_name': x.first_name,
                'last_name': x.last_name,
                'designation': x.designation,
                'experience': x.experience,
                'gender': x.gender,
                'skills': x.skills,
                'client': x.client,
                'location': x.location,
                'address': x.address,
                'mobile': x.mobile,
                'imageUrl': x.imageUrl,
                'linked_in': x.linked_in,
                'github': x.github,
                'slack': x.slack,
                'joining_date': x.joining_date,
                'dob': x.dob
            }

        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)


class RevokedTokenModel(db.Model):
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120))

    def add(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti=jti).first()
        return bool(query)


class LeavesModel(db.Model):
    __tablename__ = 'leaves'
    id = db.Column(db.Integer, primary_key=True)
    leave_type = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String, nullable=False)
    emp_id = db.Column(db.Integer, db.ForeignKey('users.emp_id'), nullable=False)
    from_date = db.Column(db.DateTime, nullable=False)
    to_date = db.Column(db.DateTime, nullable=False)
    num_of_days = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        return db.session.commit()

    @classmethod
    def get_applied_leaves(cls, pk):
        def to_json(x):
            return {
                'id': x.id,
                'leave_type': LeaveTypesModel.get_leave_type(x.leave_type),
                'description': x.description,
                'num_of_days': x.num_of_days,
                'from_date': str(x.from_date),
                'to_date': str(x.to_date),
                'status': x.status
            }

        return {'Aways': list(map(lambda x: to_json(x), LeavesModel.query.filter_by(employee_id=pk)))}

    @classmethod
    def get_all_leaves(cls):
        def to_json(x):
            return {
                'id': x.id,
                'employee_id': x.employee_id,
                'leave_type': LeaveTypesModel.get_leave_type(x.leave_type),
                'description': x.description,
                'num_of_days': x.num_of_days,
                'from_date': str(x.from_date),
                'to_date': str(x.to_date),
                'status': x.status
            }

        return {'Aways': list(map(lambda x: to_json(x), LeavesModel.query.all()))}

    @classmethod
    def get_particular_leave(cls, pk):
        return LeavesModel.query.get(pk)

    def submit_update_leave_by_id(self):
        pass


class LeaveTypesModel(db.Model):
    __tablename__ = 'leave_types'
    id = db.Column(db.Integer, primary_key=True)
    leave_type = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    num_of_days = db.Column(db.Integer, nullable=False)
    validity = db.Column(db.String, nullable=False)
    carry_forward = db.Column(db.String, nullable=False)
    employee_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now)

    @classmethod
    def get_leave_types(cls):
        def to_json(x):
            return {
                'id': x.id,
                'leave_type': x.leave_type,
                'num_of_days': x.num_of_days,
                'validity': x.validity,
                'carry_forward': x.carry_forward
            }

        return {'types': list(map(lambda x: to_json(x), LeaveTypesModel.query.all()))}

    @classmethod
    def get_leave_type(cls, pk):
        leaveType = LeaveTypesModel.query.filter_by(id=pk).first()
        return leaveType.__getattribute__('leave_type')

    @classmethod
    def get_particular_leaveType(cls, pk):
        return LeaveTypesModel.query.get(pk)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def update_to_db(self):
        db.session.commit()

    @classmethod
    def delete_leaveType(self, id):
        leaveType = LeaveTypesModel.get_particular_leaveType(id)
        db.session.delete(leaveType)
        db.session.commit()


class UserProfile(db.Model):
    __tablename__ = 'user_details'
    id = db.Column(db.Integer, primary_key=True)
    emp_id = db.Column(db.Integer, db.ForeignKey('users.emp_id'))
    first_name = db.Column(db.String(120))
    last_name = db.Column(db.String(120))
    designation = db.Column(db.String(120))
    experience = db.Column(db.String(120))
    gender = db.Column(db.String(120))
    skills = db.Column(db.String(120))
    client = db.Column(db.String(120))
    location = db.Column(db.String(120))
    address = db.Column(db.String(255))
    mobile = db.Column(db.String(255))
    imageUrl = db.Column(db.String(255))
    linked_in = db.Column(db.String(255))
    github = db.Column(db.String(255))
    slack = db.Column(db.String(255))
    joining_date = db.Column(db.String(255))
    dob = db.Column(db.String(255))
