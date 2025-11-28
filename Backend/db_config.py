# db_config.py
import sys, os

import mysql
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import os
from dotenv import load_dotenv

load_dotenv()  # loads variables from .env in project root

DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "1234")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_Name", "quantumsms")
DB_PORT = os.getenv("DB_PORT", "3306")

DB_URL = f"mysql+pymysql://dimpal:nooneinlife%401234@localhost:3306/quantumsms"

