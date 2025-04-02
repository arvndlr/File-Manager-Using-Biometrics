import psycopg2
from config import DATABASE_URL

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def create_users_table():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
    ''')
    conn.commit()
    cur.close()
    conn.close()

create_users_table()
