"""protect rule test history against rewrites"""

from alembic import op

revision = "977fd0c42ae8"
down_revision = "ec3020ae8711"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE FUNCTION guard_rule_test_history() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'Rule test review history cannot be deleted' USING ERRCODE = '23514';
            END IF;
            IF OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL OR NEW.retired_by IS NULL
               OR NEW.retired_at < OLD.created_at
               OR (to_jsonb(NEW) - 'retired_at' - 'retired_by') IS DISTINCT FROM
                  (to_jsonb(OLD) - 'retired_at' - 'retired_by') THEN
                RAISE EXCEPTION 'Rule test review permits only its first retirement' USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER rule_test_history_guard BEFORE UPDATE OR DELETE ON rule_test_links
        FOR EACH ROW EXECUTE FUNCTION guard_rule_test_history()
    """)


def downgrade():
    op.execute("DROP TRIGGER rule_test_history_guard ON rule_test_links")
    op.execute("DROP FUNCTION guard_rule_test_history()")
