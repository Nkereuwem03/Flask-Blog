"""empty message

Revision ID: b57e00b10e02
Revises: 2add29e676c2
Create Date: 2023-12-29 23:02:40.326650

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b57e00b10e02'
down_revision = '2add29e676c2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.alter_column('date',
               existing_type=sa.VARCHAR(),
               type_=sa.DateTime(),
               existing_nullable=False)
        batch_op.create_index(batch_op.f('ix_post_date'), ['date'], unique=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_post_date'))
        batch_op.alter_column('date',
               existing_type=sa.DateTime(),
               type_=sa.VARCHAR(),
               existing_nullable=False)

    # ### end Alembic commands ###
