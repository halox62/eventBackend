import json
from operator import and_, or_
from sqlite3 import IntegrityError
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import firebase_admin
from firebase_admin import credentials, storage
from datetime import datetime
from flask_cors import CORS
from datetime import datetime
from celery import Celery
from datetime import timedelta
from celery.schedules import crontab
from datetime import datetime
from sqlalchemy import and_, func
from apscheduler.schedulers.background import BackgroundScheduler
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import requests
import jwt 
from jwt import InvalidTokenError
from functools import wraps
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
import firebase_admin
from firebase_admin import credentials, auth
import os
from dotenv import load_dotenv