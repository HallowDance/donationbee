from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from vpp.config import get_settings
from vpp.db.models import Base

url = context.config.get_main_option("sqlalchemy.url") or get_settings().database_url

with create_engine(url, poolclass=NullPool).connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata)
    with context.begin_transaction():
        context.run_migrations()
