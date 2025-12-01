# Backend/db_config.py
# What to say in class: “db_config.py centralizes DB credentials and produces a safe connection URL; we keep secrets in .env not code.”

from urllib.parse import quote_plus
from dotenv import load_dotenv
import os

load_dotenv()

DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "archit@122")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "quantumsms")
DB_PORT = os.getenv("DB_PORT", "3306")

password = quote_plus(DB_PASSWORD)

DB_URL = f"mysql+pymysql://{DB_USER}:{password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
