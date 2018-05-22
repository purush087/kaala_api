"""empty message

Revision ID: 6f9d64519b67
Revises: 
Create Date: 2018-05-22 18:09:21.262062

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6f9d64519b67'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('leave_types',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('leave_type', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('num_of_days', sa.Integer(), nullable=False),
    sa.Column('validity', sa.String(), nullable=False),
    sa.Column('carry_forward', sa.String(), nullable=False),
    sa.Column('employee_id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('leaves',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('leave_type', sa.Integer(), nullable=False),
    sa.Column('description', sa.String(), nullable=False),
    sa.Column('employee_id', sa.Integer(), nullable=False),
    sa.Column('from_date', sa.DateTime(), nullable=False),
    sa.Column('to_date', sa.DateTime(), nullable=False),
    sa.Column('num_of_days', sa.Integer(), nullable=False),
    sa.Column('status', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('revoked_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=120), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('users',
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('emp_id', sa.Integer(), nullable=False),
    sa.Column('password', sa.String(length=120), nullable=False),
    sa.Column('role', sa.Integer(), nullable=False),
    sa.Column('last_sign_in_at', sa.DateTime(), nullable=True),
    sa.Column('last_sign_in_ip', sa.String(length=255), nullable=True),
    sa.Column('current_sign_in_at', sa.DateTime(), nullable=True),
    sa.Column('current_sign_in_ip', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('emp_id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('emp_id')
    )
    op.create_table('user_details',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('emp_id', sa.Integer(), nullable=True),
    sa.Column('first_name', sa.String(length=120), nullable=True),
    sa.Column('last_name', sa.String(length=120), nullable=True),
    sa.Column('designation', sa.String(length=120), nullable=True),
    sa.Column('experience', sa.String(length=120), nullable=True),
    sa.Column('gender', sa.String(length=120), nullable=True),
    sa.Column('skills', sa.String(length=120), nullable=True),
    sa.Column('client', sa.String(length=120), nullable=True),
    sa.Column('location', sa.String(length=120), nullable=True),
    sa.Column('address', sa.String(length=255), nullable=True),
    sa.Column('mobile', sa.String(length=255), nullable=True),
    sa.Column('imageUrl', sa.String(length=255), nullable=True),
    sa.Column('linked_in', sa.String(length=255), nullable=True),
    sa.Column('github', sa.String(length=255), nullable=True),
    sa.Column('slack', sa.String(length=255), nullable=True),
    sa.Column('joining_date', sa.String(length=255), nullable=True),
    sa.Column('dob', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['emp_id'], ['users.emp_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user_details')
    op.drop_table('users')
    op.drop_table('revoked_tokens')
    op.drop_table('leaves')
    op.drop_table('leave_types')
    # ### end Alembic commands ###
