# test_db_conn.py -- run this from project root with venv active

import pymysql
from Backend.db_config import DB_USER, DB_PASSWORD, DB_HOST, DB_PORT

try:
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        port=int(DB_PORT)
    )
    print("MYSQL LOGIN SUCCESS!")
    conn.close()
except Exception as e:
    print("MYSQL LOGIN FAILED:", e)
