import datetime

from flask import jsonify

from run import db
from passlib.hash import pbkdf2_sha256 as sha256


class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120))
    role = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'id': x.id,
                'email': x.email,
                'role': x.role
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
    employee_id = db.Column(db.Integer, nullable=False)
    from_date = db.Column(db.DateTime, nullable=False)
    to_date = db.Column(db.DateTime, nullable=False)
    num_of_days = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    updated_at = db.Column(db.DateTime, onupdate=datetime.datetime.now)

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def get_applied_leaves(cls, pk):
        def to_json(x):
            return {
                'id': x.id,
                'leave_type': x.leave_type,
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
                'leave_type': x.leave_type,
                'description': x.description,
                'num_of_days': x.num_of_days,
                'from_date': str(x.from_date),
                'to_date': str(x.to_date),
                'status': x.status
            }

        return {'Aways': list(map(lambda x: to_json(x), LeavesModel.query.all()))}

    def submit_update_leave_by_id(self):
        pass

class LeaveTypesModel(db.Model):
    __tablename__='leave_types'
    id = db.Column(db.Integer, primary_key=True)
    leave_type = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)

    @classmethod
    def get_leave_types(cls):
        def to_json(x):
            return {
                'id': x.id,
                'leave_type': x.leave_type
            }
        return {'types': list(map(lambda x: to_json(x), LeaveTypesModel.query.all()))}

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()