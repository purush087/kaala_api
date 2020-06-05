"""empty message

Revision ID: 90e07a733d3e
Revises: 6f9d64519b67
Create Date: 2018-05-22 18:14:36.443063

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '90e07a733d3e'
down_revision = '6f9d64519b67'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('leaves', sa.Column('emp_id', sa.Integer(), nullable=False))
    op.create_foreign_key(None, 'leaves', 'users', ['emp_id'], ['emp_id'])
    op.drop_column('leaves', 'employee_id')
    op.create_unique_constraint(None, 'users', ['emp_id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='unique')
    op.add_column('leaves', sa.Column('employee_id', sa.INTEGER(), autoincrement=False, nullable=False))
    op.drop_constraint(None, 'leaves', type_='foreignkey')
    op.drop_column('leaves', 'emp_id')
    # ### end Alembic commands ###