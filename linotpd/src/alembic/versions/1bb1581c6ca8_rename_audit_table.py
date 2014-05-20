"""rename_audit_table

Revision ID: 1bb1581c6ca8
Revises: None
Create Date: 2012-07-18 16:47:27.382649

"""

# revision identifiers, used by Alembic.
revision = '1bb1581c6ca8'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.rename_table("audit", "linotp_audit")

def downgrade():
    op.rename_table("linotp_audit", "audit")

'''
EXAMPLES

from alembic import op
import sqlalchemy as sa
from alembic import context


def upgrade():
    op.create_table(
        'account',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(50), nullable=False),
        sa.Column('description', sa.Unicode(200)),
    )
    token = sa.sql.table('Token',
	sa.sql.column('LinOtpTokenId', sa.Integer),
	sa.sql.column('LinOtpFailCount', sa.Integer)
	)
    op.execute( token.update().\
	where(token.c.LinOtpTokenId>200).\
	values({token.c.LinOtpFailCount:token.c.LinOtpFailCount+10}) )

    pass

def downgrade():
    op.drop_table('account')
    pass




'''
