"""Run the test suite in a fresh random schema of an explicit development database."""
import os
import subprocess
import sys
import uuid
import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url


def main():
    raw = os.getenv('CERTOPS_DEV_DATABASE_URL')
    if not raw:
        raise SystemExit('Set CERTOPS_DEV_DATABASE_URL to a dedicated local/CI PostgreSQL database, never production.')
    url = make_url(raw)
    schema = 'certops_test_' + uuid.uuid4().hex
    connection = psycopg.connect(host=url.host, port=url.port or 5432, dbname=url.database,
        user=url.username, password=url.password, autocommit=True)
    try:
        connection.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        test_url = url.update_query_dict({'options': '-csearch_path=' + schema})
        env = {**os.environ, 'CERTOPS_TEST_DATABASE_URL': test_url.render_as_string(hide_password=False)}
        result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.', '-v'], env=env)
        return result.returncode
    finally:
        connection.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(schema)))
        connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
