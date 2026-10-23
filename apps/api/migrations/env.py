from aegis import models  # noqa: F401
from aegis.config import require_normal_operation
from aegis.db import Base, engine
from alembic import context

target_metadata = Base.metadata
require_normal_operation()

if context.is_offline_mode():
    from aegis.config import settings

    context.configure(
        url=settings().database_url, target_metadata=target_metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    with engine().connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()
