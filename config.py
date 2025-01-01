from dotenv import load_dotenv
import os
import logging

class Config:
    load_dotenv()

    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DELAY = 0.5

    LOG_LEVEL = logging.DEBUG if os.getenv("FLASK_ENV") == "development" else logging.INFO
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = os.getenv("LOG_FILE", "app.log")

    AES_KEY = os.getenv("AES_KEY")
