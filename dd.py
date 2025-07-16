from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import re

# Configuración de la aplicación
load_dotenv()

if __name__ == '__main__':
    print('DATABASE_KEY:', os.getenv('DATABASE_KEY'))
    print('DATABASE_URL:', os.getenv('DATABASE_URL'))
