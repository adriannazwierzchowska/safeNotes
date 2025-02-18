"""Add signature to Shared Notes

Revision ID: 64bdb6216628
Revises: 2ab11eb89d7d
Create Date: 2025-01-02 17:56:36.985558

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '64bdb6216628'
down_revision = '2ab11eb89d7d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('shared_notes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('signature', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('shared_notes', schema=None) as batch_op:
        batch_op.drop_column('signature')

    # ### end Alembic commands ###
