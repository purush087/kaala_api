from flask import jsonify

from run import db
from passlib.hash import pbkdf2_sha256 as sha256


class UserModel(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120))
    # first_name = db.Column(db.String(120))
    # last_name = db.Column(db.String(120))
    # role = db.Column(db.Integer)
    # gender = db.Column(db.String(120))
    # skills = db.Column(db.String(120))
    # client = db.Column(db.String(120))
    # address = db.Column(db.String(255))
    # imageUrl = db.Column(db.String(255))
    # joining_date = db.Column(db.String(255))
    # dob = db.Column(db.String(255))

    def save_to_db(self):
        db.session \
            .add(self)
        db.session.commit()

    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()

    @classmethod
    def return_all(cls):
        def to_json(x):
            return jsonify({
                'email': x.email,
                'first_name': x.first_name,
                'last_name': x.last_name,
                'gender': x.gender,
                'skills': x.skills,
                'client': x.client,
                'address': x.address,
                'imageUrl': x.imageUrl,
                'joining_date': x.joining_date,
                'dob': x.dob,
                'role': x.role
            })

        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

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


