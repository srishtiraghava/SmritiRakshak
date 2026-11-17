"""Quick verification: list all tables in smritirakshak database."""
import psycopg

conn = psycopg.connect("host=localhost port=5432 dbname=smritirakshak user=postgres")
cur = conn.cursor()
cur.execute("""
    SELECT table_name FROM information_schema.tables 
    WHERE table_schema = 'public' 
    ORDER BY table_name
""")
print("Tables in smritirakshak:")
for row in cur.fetchall():
    print(f"  ✓ {row[0]}")

# Also check alembic version
cur.execute("SELECT version_num FROM alembic_version")
print(f"\nAlembic version: {cur.fetchone()[0]}")

cur.close()
conn.close()
