"""empty message

Revision ID: 75cf993ea271
Revises: 150e03eaa460
Create Date: 2024-01-11 10:05:27.665617

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '75cf993ea271'
down_revision = '150e03eaa460'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('disabled', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comments', schema=None) as batch_op:
        batch_op.drop_column('disabled')

    # ### end Alembic commands ###