"""Initialize new database with updated note model

Revision ID: b0985fd20e34
Revises: 
Create Date: 2024-12-27 22:15:56.730091

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b0985fd20e34'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('note', schema=None) as batch_op:
        batch_op.alter_column(
            'id',
            existing_type=sa.INTEGER(),
            nullable=False,
            autoincrement=True
        )

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column(
            'id',
            existing_type=sa.INTEGER(),
            nullable=False,
            autoincrement=True
        )
        # Explicitly name the constraints
        batch_op.create_unique_constraint('uq_user_email', ['email'])
        batch_op.create_unique_constraint('uq_user_username', ['username'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        # Explicitly drop the named constraints
        batch_op.drop_constraint('uq_user_email', type_='unique')
        batch_op.drop_constraint('uq_user_username', type_='unique')
        batch_op.alter_column(
            'id',
            existing_type=sa.INTEGER(),
            nullable=True,
            autoincrement=True
        )

    with op.batch_alter_table('note', schema=None) as batch_op:
        batch_op.alter_column(
            'id',
            existing_type=sa.INTEGER(),
            nullable=True,
            autoincrement=True
        )
        # ### end Alembic commands ###