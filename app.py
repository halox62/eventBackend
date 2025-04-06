import json
from operator import and_, or_
from sqlite3 import IntegrityError
from flask import Flask, request, jsonify, render_template_string
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
import urllib.parse
from geopy.distance import geodesic
import logging
from werkzeug.utils import secure_filename
import mimetypes
from collections import Counter
from better_profanity import profanity
from datetime import time

# Endpoint per caricare l'immagine
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



#psql -U postgres

#load_dotenv('/Users/giorgiomartucci/Documents/OutfitApp/key.env')

#FIREBASE_PUBLIC_KEYS_URL = os.getenv("FIREBASE_PUBLIC_KEYS_URL")
#FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")


FIREBASE_PUBLIC_KEYS_URL = os.getenv("FIREBASE_PUBLIC_KEYS_URL")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")


app = Flask(__name__)

CORS(app) 

profanity.load_censor_words()




def get_firebase_public_keys():
    response = requests.get(FIREBASE_PUBLIC_KEYS_URL)
    if response.status_code == 200:
        return response.json()
    raise Exception("Impossibile scaricare le chiavi pubbliche di Firebase.")

def verify_firebase_token(token):
    try:
        public_keys = get_firebase_public_keys()
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid or kid not in public_keys:
            raise InvalidTokenError("Chiave pubblica non trovata per kid.")

        public_key_pem = public_keys[kid]
        certificate = load_pem_x509_certificate(public_key_pem.encode())
        public_key = certificate.public_key()

        decoded_token = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=FIREBASE_PROJECT_ID,
            issuer=f"https://securetoken.google.com/{FIREBASE_PROJECT_ID}"
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        print("Signature has expired")
        return None 
    except InvalidTokenError as e:
        print(f"Token non valido: {e}")
        return None
    except Exception as e:
        print(f"Errore durante la verifica del token: {e}")
        return None

# Decoratore per proteggere le route
def firebase_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"msg": "Token mancante"}), 401

        try:
            token = auth_header.split(" ")[1]
            decoded_token = verify_firebase_token(token)
            if not decoded_token:
                return jsonify({"msg": "Token non valido"}), 401
        except Exception as e:
            return jsonify({"msg": f"Errore durante l'elaborazione del token: {e}"}), 401

        request.user = decoded_token
        return f(*args, **kwargs)
    return decorated_function




# Prendi l'URL del database dalle variabili d'ambiente
DATABASE_URL = os.environ.get('DATABASE_URL')  
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Configura il database
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inizializza il database
db = SQLAlchemy(app)


# Modello per il file caricato
class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String(80), nullable=False)  
    emailUser = db.Column(db.String(120), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    file_url = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(200), nullable=False)
    point = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<FileRecord {self.filename}>'

class FileSave(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailUser = db.Column(db.String(120))
    idPhoto=db.Column(db.Integer)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailUser = db.Column(db.String(120))
    idPhoto=db.Column(db.Integer)
    file_url = db.Column(db.String(200), nullable=False)
    time_stamp = db.Column(db.String(120))


# Modello per gli utenti
class UserAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailUser = db.Column(db.String(120), unique=True, nullable=True)
    userName = db.Column(db.String(80), nullable=False)  
    profileImageUrl = db.Column(db.String(200), nullable=True)
    point = db.Column(db.String(200), nullable=True)
   

# Mi piace
class LikePhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailUser = db.Column(db.String(120), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file_record.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('emailUser', 'file_id', name='_user_file_like'),)

# Modello per gli eventi
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    eventName = db.Column(db.String(120), nullable=False)
    emailUser = db.Column(db.String(120), nullable=False)
    eventCode = db.Column(db.String(80), nullable=False)  
    eventDate = db.Column(db.Date, nullable=False)
    endDate = db.Column(db.Date, nullable=False)  
    endTime = db.Column(db.Time, nullable=False)  
    latitudine = db.Column(db.String(255), nullable=False) 
    longitude = db.Column(db.String(255), nullable=False) 
    create = db.Column(db.String(80), nullable=False) 
    end = db.Column(db.String(80), nullable=False) 

class info(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idPhoto= db.Column(db.Integer)
    type = db.Column(db.String(120), nullable=False)
    brand = db.Column(db.String(120), nullable=False)
    model = db.Column(db.String(120), nullable=False)
    feedback = db.Column(db.String(80), nullable=False)  

class EventSubscibe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailUser = db.Column(db.String(120), nullable=False)
    eventCode = db.Column(db.String(80), nullable=False)  
    position = db.Column(db.String(80), nullable=False) 


# Crea tutte le tabelle definite dai modelli nel database
with app.app_context():
    db.create_all()


firebase_credentials = {
    "type": os.getenv("FIREBASE_TYPE"),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_X509_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_X509_CERT_URL"),
    "universe_domain": "googleapis.com"
}


# Inizializza Firebase Admin SDK con il file di credenziali
# Recupera le credenziali dal file .env
#firebase_credentials = os.getenv("FIREBASE_CREDENTIALS")
firebase_bucket = os.getenv("FIREBASE_BUCKET")


# Inizializza Firebase con le credenziali
cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred, {
    'storageBucket': firebase_bucket
})

bucket = storage.bucket()

def update_event_rankings():
    with app.app_context(): 
        try:
            current_datetime = datetime.now()
            completed_events = Event.query.filter(
                and_( 
                    Event.end == "false",
                    or_(
                        Event.endDate > current_datetime.date(),
                    and_(
                        Event.endDate == current_datetime.date(),
                        current_datetime.time() > Event.endTime
                    )
                )
            )
              
                
            ).all()

            
            for event in completed_events:
                print(f"ID: {event.id}, End: {event.end}, EndDate: {event.endDate}, EndTime: {event.endTime}")
            
            if not completed_events:
                print("No completed events found to process")
                return
                
            for event in completed_events:
                print(f"Processing completed event: {event.eventCode}")
                
                # Ottieni tutti gli utenti iscritti all'evento con position=true
                subscribed_users = EventSubscibe.query.filter_by(
                    eventCode=event.eventCode,
                    position="true"
                ).all()
                
                if not subscribed_users:
                   
                    continue
                
                # Crea un set di email degli utenti iscritti per ricerca veloce
                subscribed_emails = {sub.emailUser for sub in subscribed_users}
                
                # Ottieni e processa le foto solo degli utenti iscritti
                process_event_photos(event, subscribed_emails)
                
            db.session.commit()
            print("Completed events ranking update finished")
            
        except Exception as e:
            db.session.rollback()
           
            raise

def process_event_photos(event, subscribed_emails: set):

    photos_with_likes = db.session.query(
        FileRecord,
        func.count(LikePhoto.id).label('likes_count')
    ).outerjoin(
        LikePhoto,
        LikePhoto.file_id == FileRecord.id
    ).filter(
        FileRecord.code == event.eventCode,
        FileRecord.emailUser.in_(subscribed_emails)
    ).group_by(
        FileRecord.id
    ).all()
    
    if not photos_with_likes:
        return
    

    sorted_photos = sorted(photos_with_likes, key=lambda x: x.likes_count, reverse=True)
    

    for index, (photo, likes_count) in enumerate(sorted_photos):
        update_user_points(photo, index, likes_count)

def update_user_points(photo, index: int, likes_count: int):
    user = UserAccount.query.filter_by(emailUser=photo.emailUser).first()
    if not user:
       
        return
    

    score_multiplier = calculate_multiplier(index)
    event_points = score_multiplier * likes_count
    

    current_points = int(user.point) if user.point and user.point.isdigit() else 0
    

    user.point = str(current_points + event_points)
    print(f"Updated {user.emailUser} score by {event_points} points")
    

    photo.point = str(event_points)
    

    apply_penalty(user, event_points)

def calculate_multiplier(index: int) -> int:
    return 100 - index if index < 100 else 1

def apply_penalty(user, event_points: int):
    PERFORMANCE_THRESHOLD = 0.1  # 10% del punteggio totale
    PENALTY_RATE = 0.5  # 50% dei punti mancanti
    
    current_points = int(user.point) if user.point and user.point.isdigit() else 0
    min_required_points = current_points * PERFORMANCE_THRESHOLD
    
    if event_points < min_required_points:
        penalty_points = int((min_required_points - event_points) * PENALTY_RATE)
        new_points = max(0, current_points - penalty_points)  # Evita punti negativi
        user.point = str(new_points)


scheduler = BackgroundScheduler()
scheduler.add_job(update_event_rankings, 'cron', hour=0, minute=0)
scheduler.start()



@app.route('/')
def healthcheck():
    return 'OK', 200


def delete_firebase_user(user_email):
    try:
        user = auth.get_user_by_email(user_email)
        auth.delete_user(user.uid)
        return True
    except auth.UserNotFoundError:
        return False
    except Exception as e:
        return False
    

@app.route('/delete_account', methods=['POST'])
@firebase_required
def delete_account():
    try:
        authenticated_email = request.user.get("email")

       
        request_data = request.get_json()
        submitted_email = request_data.get('email', '').strip()

    
        if not submitted_email or submitted_email != authenticated_email:
            return jsonify({'error': 'error'}), 403

      
        user = UserAccount.query.filter_by(emailUser=authenticated_email).first()
        
        if not user:
            return jsonify({'error': 'error'}), 404

        profile_image_url = user.profileImageUrl
        file_records = FileRecord.query.filter_by(emailUser=authenticated_email).all()
        file_ids = [record.id for record in file_records]

        firebase_files_deleted = delete_firebase_storage_files(authenticated_email, profile_image_url, file_records)
        
        firebase_user_deleted = delete_firebase_user(authenticated_email)

        with db.session.begin_nested():
            if file_ids:
                LikePhoto.query.filter(LikePhoto.file_id.in_(file_ids)).delete(synchronize_session=False)

            info.query.filter(info.idPhoto.in_(file_ids)).delete(synchronize_session=False)
            
           
            models_to_delete = [
                FileSave,
                Event,
                EventSubscibe
            ]
            
            for model in models_to_delete:
                model.query.filter_by(emailUser=authenticated_email).delete(synchronize_session=False)
            
           
            FileRecord.query.filter_by(emailUser=authenticated_email).delete(synchronize_session=False)

           
            db.session.delete(user)
            
          
            db.session.commit()


        return jsonify({
            'message': 'Account, dati associati ed elementi Firebase eliminati con successo',
            'firebase_user_deleted': firebase_user_deleted,
            'firebase_files_deleted': firebase_files_deleted
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': 'Si è verificato un errore durante l\'eliminazione dell\'account',
            'details': str(e)
        }), 500

def delete_firebase_storage_files(email, profile_image_url=None, file_records=None):
    try:
        bucket = storage.bucket()
        
        user_folder_prefix = f"users/{email}/"
             
        user_blobs = bucket.list_blobs(prefix=user_folder_prefix)
        
        for blob in user_blobs:
            blob.delete()
         

        base_url = "https://storage.googleapis.com/outfitsocial-a6124.appspot.com/"
        profile_image_path = profile_image_url.replace(base_url, '')
        
        profile_blob = bucket.blob(profile_image_path)
        
        
        profile_blob.delete()
   
        
        remaining_user_blobs = list(bucket.list_blobs(prefix=user_folder_prefix))
        if not remaining_user_blobs:
           
            return True
        else:
            return False

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'error': 'Si è verificato un errore durante l\'eliminazione dell\'account',
            'details': str(e)
        }), 500

@app.route('/upload', methods=['POST'])
@firebase_required
def upload_image():
    try:
        email = request.user.get("email")
        if not email:
            return jsonify({"error": "Autenticazione richiesta"}), 401

        if 'file' not in request.files:
            return jsonify({"error": "Nessun file caricato"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "Nome file non valido"}), 400

        if request.content_length > MAX_FILE_SIZE:
            return jsonify({"error": f"File troppo grande. Dimensione massima: {MAX_FILE_SIZE/1024/1024}MB"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": f"Tipo file non supportato. Formati permessi: {', '.join(ALLOWED_EXTENSIONS)}"}), 400

        user = UserAccount.query.filter_by(emailUser=email).first()
        if not user:
            return jsonify({"error": "Utente non trovato"}), 404

        secure_name = secure_filename(file.filename)
        
        existing_file = FileRecord.query.filter_by(filename=secure_name).first()
        if existing_file:
            return jsonify({"error": "File già caricato"}), 400

        try:
            bucket = storage.bucket()
            blob_path = f'images/{email}/{secure_name}'
            blob = bucket.blob(blob_path)
            
            content_type = file.content_type or mimetypes.guess_type(secure_name)[0]
            blob.upload_from_file(file, content_type=content_type)
            blob.make_public()

            new_file = FileRecord(
                userName=user.userName,
                emailUser=email,
                filename=secure_name,
                file_url=blob.public_url,
                code='null',
                point="0"
            )
            
            db.session.add(new_file)
            db.session.commit()

            file_id = new_file.id

            return jsonify({
                'message': 'File caricato con successo',
                'id': file_id
            }), 200

        except Exception as e:
            logging.error(f"Errore durante l'upload: {str(e)}")
            db.session.rollback()
            return jsonify({"error": "Errore durante il salvataggio del file"}), 500

    except Exception as e:
        logging.error(f"Errore generale in upload_image: {str(e)}")
        return jsonify({"error": "Errore del server"}), 500


@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')

    access_token = create_access_token(identity={'email': email})

    return jsonify(access_token=access_token)


@app.route('/register', methods=['POST'])
def register():
    try:

        if 'profileImage' not in request.files or 'email' not in request.form or 'userName' not in request.form or 'age' not in request.form:
            return jsonify({"error": "Missing data or image"}), 400
        
        email = request.form['email']
        userName = request.form['userName']
        profileImage = request.files['profileImage']
        age = request.form['age']
        
        if int(age) <16:
            return jsonify({"error": "invalid age"}), 400


        existing_user = UserAccount.query.filter_by(emailUser=email).first()
        if existing_user:
            return jsonify({"error": "Email already registered"}), 400

        bucket = storage.bucket()
        blob = bucket.blob(f'images/profile/{profileImage.filename}')
        blob.upload_from_file(profileImage)
        blob.make_public() 

        profileImageUrl = blob.public_url

        new_user = UserAccount(emailUser=email, userName=userName, profileImageUrl=profileImageUrl, point="0")
        
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"register":"ok"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/profileInformation', methods=['GET'])
def profile_with_images():
    email = request.args.get("email")

    save=0

    if not email:
        return jsonify({"error": "Email not provided"}), 400

    user = UserAccount.query.filter_by(emailUser=email).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404

    images = []
    blobs = bucket.list_blobs(prefix=f'images/{email}/')


    file_records = FileRecord.query.filter_by(emailUser=email).all()
    file_records_dict = {record.file_url.split("/")[-1]: record.id for record in file_records}
    saved_photos = FileSave.query.filter_by(emailUser=email).all()
    save_counts = Counter([saved.idPhoto for saved in saved_photos])

    for blob in blobs:
        blob.make_public()
        file_name = blob.name.split("/")[-1]
        file_id = file_records_dict.get(file_name, None)
        
        if file_id is not None:
            image_info = {
                "id": file_id,
                "url": blob.public_url,
                "saves": save_counts.get(file_id, 0)  
            }
            save+=save_counts.get(file_id, 0) 
            images.append(image_info)

    return jsonify({
        "userName": user.userName,
        "profileImageUrl": user.profileImageUrl,
        "point": user.point,  
        "images": images,
        "save":save
    }), 200



@app.route('/getImage', methods=['POST'])
@firebase_required
def get_Image():
    email = request.user.get("email")

    if not email:
        return jsonify({"error": "Email not provided"}), 400

    images = []
    blobs = bucket.list_blobs(prefix=f'images/{email}/')

    
    file_records = FileRecord.query.filter_by(emailUser=email).all()
    file_records_dict = {record.file_url.split("/")[-1]: record.id for record in file_records}

    
    all_saved_photos = FileSave.query.with_entities(FileSave.idPhoto).all()
    saved_photo_ids = [photo[0] for photo in all_saved_photos]

   
    photo_counts = {}
    for file_id in saved_photo_ids:
        if any(record.id == file_id for record in file_records):
            photo_counts[file_id] = photo_counts.get(file_id, 0) + 1

    for blob in blobs:
        blob.make_public()
        file_name = blob.name.split("/")[-1]
        file_id = file_records_dict.get(file_name, None)
        
        if file_id is not None:
            image_info = {
                "id": file_id,  
                "url": blob.public_url,
                "point": photo_counts.get(file_id, 0)  
            }
            images.append(image_info)

    return jsonify({"images": images}), 200
    

@app.route('/profile', methods=['POST'])
@firebase_required
def get_profile():
    try:
        email = request.user.get("email")

        if not email:
            return jsonify({"error": "Email not provided"}), 400

        user = UserAccount.query.filter_by(emailUser=email).first()
        if user is None:
            return jsonify({"error": "User not found"}), 404
        
        # Ottieni tutti gli idPhoto dalla tabella FileSave
        saved_photos = FileSave.query.with_entities(FileSave.idPhoto).all()
        
        # Conta quanti di questi idPhoto corrispondono a file dell'utente in FileRecord
        file_count = (FileRecord.query
                     .filter(FileRecord.id.in_([photo[0] for photo in saved_photos]))
                     .filter_by(emailUser=email)
                     .count())

        return jsonify({
            "userName": user.userName,
            "profileImageUrl": user.profileImageUrl,
            "point": user.point,
            "save": file_count  
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route('/profileS', methods=['POST'])
@firebase_required
def get_profileS():

    try:
        
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({"error": "Email not provided"}), 400

        user = UserAccount.query.filter_by(emailUser=email).first()
        if user is None:
            return jsonify({"error": "User not found"}), 404
        
        # Ottieni tutti gli idPhoto dalla tabella FileSave
        saved_photos = FileSave.query.with_entities(FileSave.idPhoto).all()
        
        # Conta quanti di questi idPhoto corrispondono a file dell'utente in FileRecord
        file_count = (FileRecord.query
                     .filter(FileRecord.id.in_([photo[0] for photo in saved_photos]))
                     .filter_by(emailUser=email)
                     .count())

        return jsonify({
            "userName": user.userName,
            "profileImageUrl": user.profileImageUrl,
            "point": user.point,
            "save": file_count  
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/getImageS', methods=['POST'])
@firebase_required
def get_ImageS():
    
    data = request.get_json()
    email = data.get('email')

   
    if not email:
        return jsonify({"error": "Email not provided"}), 400

    images = []
    blobs = bucket.list_blobs(prefix=f'images/{email}/')

    file_records = FileRecord.query.filter_by(emailUser=email).all()

    file_records_dict = {record.file_url.split("/")[-1]: record.id for record in file_records}

    saved_photos = FileSave.query.filter_by(emailUser=email).all()

    photo_counts = Counter([saved.idPhoto for saved in saved_photos])

    for blob in blobs:
        blob.make_public()

        file_name = blob.name.split("/")[-1]
        
        file_id = file_records_dict.get(file_name, None)
        
        if file_id is not None:
            image_info = {
                "id": file_id,  
                "url": blob.public_url,
                "point": photo_counts.get(file_id, 0) 
            }
            images.append(image_info)

    return jsonify({"images": images}), 200

@app.route('/createEvent', methods=['POST'])
@firebase_required
def createEvent():
    try:
        
        required_fields = {
            'email': request.user.get("email"),
            'eventName': request.form.get('eventName'),
            'eventCode': request.form.get('eventCode'),
            'eventDate': request.form.get('eventDate'),
            'eventTime': request.form.get('eventTime'),
            'endDate': request.form.get('endDate'),
            'endTime': request.form.get('endTime'),
            'latitudine': request.form.get('latitudine'),
            'longitude': request.form.get('longitude'),
            'create': request.form.get('create')
        }
       
        missing_fields = [field for field, value in required_fields.items() if not value or value.strip() == '']
        if missing_fields:
            return jsonify({
                "error": f"Missing required fields: {', '.join(missing_fields)}"
            }), 400

       
        try:
            
            event_date = datetime.strptime(required_fields['eventDate'], '%Y-%m-%d').date()
            end_date = datetime.strptime(required_fields['endDate'], '%Y-%m-%d').date()

          
            event_time = datetime.strptime(required_fields['eventTime'], '%H:%M').time()
            end_time_str = required_fields['endTime'].strip()
            end_time = datetime.strptime(end_time_str, '%H:%M').time()

            
            event_datetime = datetime.combine(event_date, event_time)
            end_datetime = datetime.combine(end_date, end_time)

            
            if event_datetime >= end_datetime:
                return jsonify({
                    "error": "Event end time must be after start time"
                }), 400

        

        except ValueError as ve:
            app.logger.error(f"Parsing error: {str(ve)}")
            return jsonify({
                "error": f"Invalid date or time format: {str(ve)}. Use YYYY-MM-DD for dates and HH:MM for times."
            }), 400

       
        try:
            lat = float(required_fields['latitudine'])
            lon = float(required_fields['longitude'])
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                return jsonify({
                    "error": "Invalid coordinates: latitude must be between -90 and 90, longitude between -180 and 180"
                }), 400
        except ValueError:
            return jsonify({
                "error": "Latitude and longitude must be valid numbers"
            }), 400

       
        existing_event = Event.query.filter_by(eventCode=required_fields['eventCode']).first()
        if existing_event:
            return jsonify({
                "error": "Event code already exists"
            }), 400

       
        new_event = Event(
            eventName=required_fields['eventName'],
            emailUser=required_fields['email'],
            eventCode=required_fields['eventCode'],
            eventDate=event_date,
            endDate=end_date,
            endTime=end_time,
            latitudine=required_fields['latitudine'],
            longitude=required_fields['longitude'],
            create=required_fields['create'],
            end="false"
        )

       
        db.session.add(new_event)
        db.session.commit()


        return jsonify({
            "message": "Event created successfully",
            "eventCode": required_fields['eventCode']
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating event: {str(e)}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500

@app.route('/getCreateEvent', methods=['POST'])#query che ritorna gli eventi che sono stati creati da un'email
@firebase_required
def getCreateEvent():
    try:
       
        email = request.user.get("email")
        
       
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        
       
        eventi = Event.query.filter_by(emailUser=email).all()

       
        if not eventi:
            return jsonify({"message": "No events found for this email"}), 404

       
        return jsonify({"event_codes": [evento.eventCode for evento in eventi]}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/get_coordinate', methods=['POST'])
@firebase_required
def get_coordinate():
    try:
        data = request.get_json()
    
        code = data.get('code')
       
        event = Event.query.filter_by(eventCode=code).first()
        
       
        if not event:
            return jsonify({"error": "Event not found"}), 404
        
        
        return jsonify({
            "latitude": event.latitudine,
            "longitude": event.longitude
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/getEventCode', methods=['GET'])
@firebase_required
def getEventCode():
    try:
        email = request.user.get("email")
        client_time_str = request.args.get("clientTime") 
        
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        
        if not client_time_str:
            return jsonify({"error": "Client time not provided"}), 400

        try:
            client_time = datetime.strptime(client_time_str, "%H:%M").time()
        except ValueError:
            return jsonify({"error": "Invalid time format"}), 400
        
        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()
        subscribed_event_codes = [sub.eventCode for sub in subscribed_events]

        if not subscribed_event_codes:
            return jsonify({"message": "No subscribed events found for this email"}), 404

        current_date = datetime.now().date()

        ongoing_events = Event.query.filter(
            Event.eventCode.in_(subscribed_event_codes),
            Event.end == "false",
            or_(
                current_date > Event.eventDate, 
                and_(
                    current_date == Event.eventDate,
                    client_time >= Event.endTime  # Usa l'orario del client
                )
            )
        ).all()

        if not ongoing_events:
            return jsonify({"event_codes": None}), 200

        return jsonify({"event_codes": [event.eventCode for event in ongoing_events]}), 200

    except Exception as e:
        print(str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/createGetEventDates', methods=['GET'])#ritorna le date degli eventi create da un'email
@firebase_required
def get_event_dates():
    try:

        email = request.user.get("email")


      
        if not email:
            return jsonify({"error": "Email not provided"}), 400

       
        events = Event.query.filter_by(emailUser=email , create="yes").all()

       
        event_dates = [event.eventDate.strftime('%Y-%m-%d') for event in events]
        

        return jsonify(event_dates), 200 
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route('/subscribeGetEventDates', methods=['GET'])#ritorna le date degli eventi dove partecipa un'email
@firebase_required
def get_event_datesAdd():
    try:
        email = request.user.get("email")


        if not email:
            return jsonify({"error": "Email not provided"}), 400


        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()

        event_codes = [event.eventCode for event in subscribed_events]

        events = Event.query.filter(Event.eventCode.in_(event_codes)).all()


        event_dates = [event.eventDate.strftime('%Y-%m-%d') for event in events]

        return jsonify(event_dates), 200  
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    


@app.route('/events_by_date', methods=['POST'])
@firebase_required
def get_events_by_date():
    data = request.json
    email = request.user.get("email")
    event_date_str = data.get('date')

    if not event_date_str:
        return jsonify({'message': 'Data richiesta mancante'}), 400

    try:
        # Parse and validate date format
        event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date()
        
        # Get all event codes user has access to
        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()
        created_events = Event.query.filter_by(emailUser=email, create="yes").all()
        event_codes = [sub.eventCode for sub in subscribed_events] + [evn.eventCode for evn in created_events]

        # Get events for the specified date that user has access to
        events = Event.query.filter(
            Event.eventCode.in_(event_codes),
            Event.eventDate == event_date
        ).all()

        if not events:
            return jsonify({'message': 'Nessun evento trovato per questa data'}), 404

        events_list = [{
            'id': event.id,
            'eventName': event.eventName,
            'emailUser': event.emailUser,
            'eventCode': event.eventCode,
            'eventDate': event.eventDate.strftime('%Y-%m-%d'),
            'endDate': event.endDate.strftime('%Y-%m-%d'),
            'endTime': event.endTime.strftime('%H:%M:%S'),
            'longitude': event.longitude,
            'latitudine': event.latitudine
        } for event in events]

        return jsonify({'events': events_list}), 200

    except ValueError as e:
        return jsonify({'message': 'Formato della data non valido. Usa YYYY-MM-DD.'}), 400
    except Exception as e:
        return jsonify({'message': f'Errore del server: {str(e)}'}), 500
    

@app.route('/addEvent', methods=['POST'])
@firebase_required
def addEvent():
    try:
       
        data = request.json
        email = request.user.get("email")
        code = data.get('code')

       
        if not code:
            return jsonify({'message': 'Event code is required'}), 400

        
        event = Event.query.filter_by(eventCode=code).first()
        if not event:
            return jsonify({'message': 'Invalid event code'}), 404
        
        subscribeUser = EventSubscibe.query.filter_by(emailUser=email, eventCode=code).first()
        if subscribeUser:
            return jsonify({'message': 'Registration already completed'}), 400


       
        subscribeUser = EventSubscibe.query.filter_by(emailUser=email, eventCode=code).first()
        if subscribeUser:
            return jsonify({'message': 'Registration already completed'}), 400

       
        new_subscription = EventSubscibe(
            emailUser=email,
            eventCode=code,
            position="true" 
        )

        db.session.add(new_subscription)
        db.session.commit()
        
        return jsonify({'message': 'Successfully registered to event'}), 200

    except Exception as e:
        db.session.rollback()  
        return jsonify({'message': 'Internal server error'}), 500

    

@app.route('/uploadEventImage', methods=['POST'])
@firebase_required
def uploadEventImage():
    try:
        email = request.user.get("email")
        if not email:
            return jsonify({"error": "Autenticazione richiesta"}), 401

        required_fields = ['eventCode', 'latitudine', 'longitudine']
        if not all(field in request.form for field in required_fields):
            return jsonify({"error": "Parametri mancanti"}), 400
            
        if 'image' not in request.files:
            return jsonify({"error": "Nessun file caricato"}), 400

        code = request.form['eventCode']
        file = request.files['image']
        
        try:
            latitudine = float(request.form['latitudine'])
            longitudine = float(request.form['longitudine'])
        except ValueError:
            return jsonify({"error": "Coordinate non valide"}), 400

        user = UserAccount.query.filter_by(emailUser=email).first()
        if not user:
            return jsonify({"error": "Utente non trovato"}), 404
        
        event = Event.query.filter_by(eventCode=code).first()
        if not event:
            return jsonify({"error": "Evento non trovato"}), 404
        
        if(event.end=="true"):
            return jsonify({"error": "Evento finito"}), 404
        
        and_(Event.end=="false",
                or_(
                    datetime.now().date()>Event.endDate,
                    and_(
                        Event.endDate == datetime.now().date(),
                        Event.endTime >= datetime.now().time()
                    )
                )
            )
    
        event_location = (float(event.latitudine), float(event.longitude))
        user_location = (latitudine, longitudine)
        distance = geodesic(user_location, event_location).meters
        
        if distance > 1000: 
            return jsonify({
                "error": "Sei troppo lontano dall'evento",
                "distance": round(distance)
            }), 403

        if FileRecord.query.filter_by(code=code, filename=file.filename).first():
            return jsonify({"error": "File già caricato per questo evento"}), 400

        filename = secure_filename(file.filename)
        
        bucket = storage.bucket()
        blob_path = f'images/{email}/{filename}'
        blob = bucket.blob(blob_path)
        
        content_type = file.content_type
        blob.upload_from_file(file, content_type=content_type)
        blob.make_public()

        new_file = FileRecord(
            userName=user.userName,
            emailUser=email,
            filename=filename,
            file_url=blob.public_url,
            code=code,
            point="0"
        )
        
        db.session.add(new_file)
        db.session.commit()
        file_id = new_file.id

          
        return jsonify({
            'message': 'File caricato con successo',
            'file_url': blob.public_url,
             'id': file_id
        }), 200

    except Exception as e:
        logging.error(f"Error in uploadEventImage: {str(e)}")
        return jsonify({"error": "Errore del server"}), 500
    

@app.route('/nameByCode', methods=['POST'])  # Query che ritorna il nome di un evento per un determinato codice
@firebase_required
def NameByCode():
    try:
        data = request.json
        code = data.get('code')

        if not code:
            return jsonify({"error": "Event code not provided"}), 400
    
        
        event = Event.query.filter_by(eventCode=code).first()


        if event:
            name = event.eventName

        endTime=event.endTime.strftime('%H:%M:%S')
        startDate=event.eventDate.strftime('%Y-%m-%d')


        name_res = {"name": name, "EndTime":endTime, "startDate":startDate} 


        if not name_res:
            return jsonify({"message": "No name for this event code."}), 404
        
        
        return jsonify(name_res), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_user_profiles', methods=['POST'])  # Query che ritorna le foto profilo di un evento
@firebase_required
def photoProfilesByEvent():
    try:
        data = request.json
        code = data.get('code')

        if not code:
            return jsonify({"error": "Event code not provided"}), 400
        
        events = EventSubscibe.query.filter_by(eventCode=code).all()

        emails = [event.emailUser for event in events]

        profiles = [UserAccount.query.filter_by(emailUser=email).all() for email in emails]

        profiles = [profile for profile in profiles if profile]

        image_profiles = [{"image_path": profile.profileImageUrl} for profile in profiles]

        if not image_profiles:
            return jsonify({"message": "No images found for this event code."}), 404

        return jsonify(image_profiles), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/photoByCode', methods=['POST'])
@firebase_required
def photoByCode():
    try:
        data = request.json
        code = data.get('code')
        
        if not code:
            return jsonify({"error": "Event code not provided"}), 400
        
        query = (db.session.query(
                 FileRecord,
                 UserAccount.profileImageUrl,
                 UserAccount.emailUser,
                 db.func.count(LikePhoto.id).label('like_count'),
                 db.func.count(FileSave.id).label('save_count')
              )
              .join(UserAccount, FileRecord.userName == UserAccount.userName)
              .outerjoin(LikePhoto, FileRecord.id == LikePhoto.file_id)
              .outerjoin(FileSave, FileRecord.id == FileSave.idPhoto)
              .filter(FileRecord.code == code)
              .group_by(FileRecord.id, UserAccount.profileImageUrl, UserAccount.emailUser)
              .all())
        
        image_links = [{
            "id": img[0].id,
            "image_path": img[0].file_url,
            "likes": img[3],
            "name": img[0].userName,
            "image_profile": img[1],
            "email": img[2],
            "point": img[4] 
        } for img in query]
        
        if not image_links:
            return jsonify({"message": "No images found for this event code."}), 404
        
        return jsonify(image_links), 200
    except Exception as e:
        app.logger.error(f"Error in photoByCode: {str(e)}")
        return jsonify({"error": str(e)}), 500
    


@app.route('/increment_like', methods=['POST'])
@firebase_required
def increment_like():
    try:
        data = request.get_json()
        
        image_id = data.get('photoId')
        email = request.user.get("email")

        if not image_id or not email:
            return jsonify({"error": "Image ID or email not provided"}), 400

        file_record = FileRecord.query.filter_by(file_url=image_id).first()

        if not file_record:
            return jsonify({"error": "Image not found"}), 404

        existing_like = LikePhoto.query.filter_by(emailUser=email, file_id=file_record.id).first()

        if existing_like:
            return jsonify({"message": "User has already liked this photo"}), 403

        new_like = LikePhoto(emailUser=email, file_id=file_record.id)
        db.session.add(new_like)

        try:
            file_record.point = str(int(file_record.point) + 1)
        except ValueError:
            return jsonify({"error": "Invalid point value"}), 400
        

        db.session.commit()

        return jsonify({"message": "Like incremented successfully", "new_point": file_record.point}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    




@app.route('/get_like', methods=['GET'])
@firebase_required
def get_like():
    try:
        email = request.user.get("email")

        liked_photos = db.session.query(
            FileRecord,
            db.func.count(LikePhoto.id).label('like_count')
        ).join(
            LikePhoto, FileRecord.id == LikePhoto.file_id
        ).filter(
            FileRecord.id.in_(
                db.session.query(LikePhoto.file_id).filter(LikePhoto.emailUser == email)
            )
        ).group_by(
            FileRecord.id
        ).all()

        image_links = [{
            "image_path": record.file_url, 
            "likes": like_count
        } for record, like_count in liked_photos]

        if not image_links:
            return jsonify({"message": "No liked images found for this user."}), 404
        
        return jsonify(image_links), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    

@app.route('/get_ranking', methods=['POST'])
@firebase_required
def get_ranking():
    try:
        data = request.get_json()
        event_code = data.get('eventCode')

        if not event_code:
            return jsonify({"error": "Event code not provided"}), 400

        
        ranked_photos = (db.session.query(
                FileRecord,
                db.func.count(LikePhoto.id).label('like_count')
            )
            .outerjoin(LikePhoto, FileRecord.id == LikePhoto.file_id)
            .filter(FileRecord.code == event_code)
            .group_by(FileRecord.id)
            .order_by(db.func.count(LikePhoto.id).desc())
            .all())

        photos = []
        for photo, like_count in ranked_photos:
            photos.append({
                'image_path': photo.file_url,
                'likes': like_count,
            })

        return jsonify({'photos': photos}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    

@app.route('/set_position_true', methods=['POST'])
@firebase_required
def set_position_true():
    try:
        data = request.get_json()
        email = request.user.get("email")
        event_code = data.get('eventCode')

        if not email or not event_code:
            return jsonify({"error": "Email or event code not provided"}), 400

        subscription = EventSubscibe.query.filter_by(emailUser=email, eventCode=event_code).first()

        if not subscription:
            return jsonify({"error": "Subscription not found"}), 404

        subscription.position = "true"
        
        db.session.commit()

        return jsonify({"message": "Position set to true successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/get_scoreboard', methods=['GET'])
@firebase_required
def get_scoreboard():
    try:
        current_user_email = request.user.get("email")
        

        all_users_ranked = (
            db.session.query(UserAccount)
            .order_by(UserAccount.point.desc())
            .all()
        )
        
        top_users = all_users_ranked[:100]
        
        if not top_users:
            return jsonify({"message": "No users found"}), 404
        
        current_user_position = None
        current_user_data = None
        
        for position, user in enumerate(all_users_ranked):
            if user.emailUser == current_user_email:
                current_user_position = position + 1 
                current_user_data = {
                    "id": user.id,
                    "emailUser": user.emailUser,
                    "userName": user.userName,
                    "profileImageUrl": user.profileImageUrl,
                    "point": user.point,
                    "position": current_user_position
                }
                break
        
        scoreboard = []
        for position, user in enumerate(top_users):
            scoreboard.append({
                "id": user.id,
                "emailUser": user.emailUser,
                "userName": user.userName,
                "profileImageUrl": user.profileImageUrl,
                "point": user.point,
                "position": position + 1  
            })
        
        return jsonify({
            "scoreboard": scoreboard, 
            "currentUser": current_user_data
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/get_user_ranking', methods=['GET'])
@firebase_required
def get_user_ranking():
    try:

        email = request.user.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        user_query = db.session.query(
            UserAccount.id,
            UserAccount.emailUser,
            UserAccount.userName,
            UserAccount.point,
            db.func.rank().over(order_by=UserAccount.point.desc()).label('rank')
        ).filter(UserAccount.emailUser == email).subquery()

        user_data = db.session.query(
            user_query.c.emailUser,
            user_query.c.userName,
            user_query.c.point,
            user_query.c.rank
        ).first()

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        user_rank = user_data.rank

        ranking_query = db.session.query(
            UserAccount.emailUser,
            UserAccount.userName,
            UserAccount.point,
            db.func.rank().over(order_by=UserAccount.point.desc()).label('rank')
        ).subquery()

        surrounding_users = db.session.query(
            ranking_query.c.emailUser,
            ranking_query.c.userName,
            ranking_query.c.point,
            ranking_query.c.rank
        ).filter(
            ranking_query.c.rank >= user_rank - 10,
            ranking_query.c.rank <= user_rank + 10
        ).order_by(ranking_query.c.rank).all()

        result = {
            "user": {
                "emailUser": user_data.emailUser,
                "userName": user_data.userName,
                "point": user_data.point,
                "rank": user_rank
            },
            "surrounding_users": [
                {
                    "emailUser": user.emailUser,
                    "userName": user.userName,
                    "point": user.point,
                    "rank": user.rank
                }
                for user in surrounding_users
            ]
        }

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/delete_photo_by_url', methods=['POST'])
@firebase_required
def delete_photo_by_url():
    try:
        photo_url = request.json.get('image_url')
        if not photo_url:
            return jsonify({'error': 'URL della foto mancante'}), 400

        photo = FileRecord.query.filter_by(file_url=photo_url).first()
        if not photo:
            return jsonify({'error': 'Foto non trovata nel database'}), 404
       
        likes = LikePhoto.query.filter_by(file_id=photo.id).all()
     
        for like in likes:
            db.session.delete(like)

        db.session.flush()

        info_entries = info.query.filter_by(idPhoto=photo.id).all()
        for entry in info_entries:
            db.session.delete(entry)

        db.session.flush()

        file_saves = FileSave.query.filter_by(idPhoto=photo.id).all()
        for save in file_saves:
            db.session.delete(save)

        db.session.flush()


        FileRecord.query.filter_by(id=photo.id).delete()
        
        db.session.flush()
        
        db.session.commit()
        
        check_photo = FileRecord.query.filter_by(id=photo.id).first()
        if check_photo is not None:
            return jsonify({'error': 'Impossibile eliminare la foto'}), 500
        

            
        decoded_url = urllib.parse.unquote(photo_url)
        file_name = decoded_url.split('outfitsocial-a6124.appspot.com/')[1]
        
        bucket = storage.bucket()
        blob = bucket.blob(file_name)
        if blob.exists():
            blob.delete()
        

        return jsonify({'message':"ok"}), 200


    except Exception as e:
        return jsonify({'error': 'Errore generico', 'details': str(e)}), 500


@app.route('/search_profiles', methods=['POST'])
@firebase_required
def search_profiles():
    try:
        data = request.get_json()
        query = data.get('profilo', '').strip()
        email = request.user.get("email")

        if not query:
            return jsonify({"msg": "Query non fornita"}), 400


        
        profiles = UserAccount.query.filter(
            UserAccount.userName.ilike(f"{query}%"),  
            UserAccount.emailUser != email
        ).all()


        if not profiles:
            return jsonify({"msg": "Nessun profilo trovato"}), 200

        return jsonify({
            "profiles": [profile.userName for profile in profiles],
            "emails": [profile.emailUser for profile in profiles],
            "images": [profile.profileImageUrl for profile in profiles]
        }), 200

    except Exception as e:
        print(f"Errore durante la ricerca dei profili: {e}")
        return jsonify({"msg": "Errore interno del server"}), 500
    

@app.route('/creator', methods=['GET'])
@firebase_required
def creator():
    try:
        email = request.user.get("email")
        if not email:
            return jsonify({"msg": "Utente non autenticato"}), 401
        
        event = Event.query.filter(Event.emailUser == email, Event.create == "yes").first()
        if not event:
            return jsonify({"msg": "not creator"}), 400

        return jsonify({"msg": "creator"}), 200

    except Exception as e:
        return jsonify({"msg": "Errore interno del server"}), 500
    
@app.route('/delete_event', methods=['POST'])
@firebase_required
def delete_event():
    try:

        data = request.get_json()
        event_code = data.get("eventCode")
        email = request.user.get("email")
        
        if not event_code:
            return jsonify({"msg": "Codice evento mancante"}), 400
        
        event = Event.query.filter(Event.eventCode==event_code, Event.emailUser==email).first()
        
        if not event:
            return jsonify({"msg": "Evento non trovato o non autorizzato"}), 404
        
        EventSubscibe.query.filter_by(eventCode=event.eventCode).delete()

        db.session.delete(event)

        db.session.commit()

        return jsonify({"msg": "Evento cancellato con successo"}), 200

    except Exception as e:
        db.session.rollback()
        print(f"Errore: {e}")
        return jsonify({"msg": "Errore interno del server"}), 500
    


@app.route('/profilePage', methods=['GET'])
def profile_page():
    email = request.args.get('email')
    if not email:
        return jsonify({"msg": "Email mancante"}), 400

    html_template = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profilo Utente</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        :root {
            --surface-variant: #f5f5f5;
            --primary-green: rgb(76, 175, 80);
            --primary-blue: #1e88e5;
        }

        body {
            background-color: #fafafa;
            display: block;
            padding: 20px 0;
            min-height: 100vh;
        }

        .profile-card {
            background-color: white;
            border-radius: 16px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }

        .grid-item {
            position: relative;
            border-radius: 8px;
            overflow: hidden;
            background-color: var(--surface-variant);
            cursor: pointer;
            transition: transform 0.3s ease;
            aspect-ratio: 1;
        }

        .grid-item img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        .saves-overlay {
            position: absolute;
            bottom: 8px;
            right: 8px;
            background-color: rgba(0, 0, 0, 0.7);
            color: white;
            padding: 2px 6px;
            border-radius: 12px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        #imageModal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 50;
        }

        #imageModal img {
            max-height: 80vh;
            max-width: 80vw;
            object-fit: contain;
            border-radius: 8px;
            transition: transform 0.3s ease;
        }

        .points-badge, .total-saves {
            text-white;
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 8px 16px; /* Uniforma le dimensioni */
            font-size: 16px; /* Dimensione del testo uniforme */
            border-radius: 12px; /* Spigoli smussati */
        }

        .points-badge {
            background-color: var(--primary-green);
        }

        .total-saves {
            background-color: var(--primary-blue);
        }

        .loading-spinner {
            border: 4px solid var(--surface-variant);
            border-top: 4px solid var(--primary-green);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="main-container max-w-4xl mx-auto px-4">
        <!-- Profilo utente -->
        <div class="profile-card p-6 mb-6">
            <div class="flex flex-col sm:flex-row items-center sm:space-x-6">
                <div class="flex-shrink-0 mb-4 sm:mb-0">
                    <img id="profileImage" 
                         class="w-24 h-24 rounded-full object-cover shadow-md border-2 border-white"
                         src=""
                         alt="Immagine profilo"
                         onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22><path fill=%22%23666%22 d=%22M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM6 12a6 6 0 1 1 12 0v1H6v-1z%22/></svg>'">
                </div>
                <div class="text-center sm:text-left">
                    <h1 id="userName" class="text-2xl font-bold mb-2">Utente</h1>
                    <div class="flex flex-col sm:flex-row items-center sm:space-x-4">
                        <div class="points-badge">
                            <span id="points">0 points</span>
                        </div>
                        <div id="totalSaves" class="total-saves">
                            <svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                                <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
                            </svg>
                            <span>0 save</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Spinner di caricamento -->
        <div id="loadingSpinner" class="text-center hidden">
            <div class="loading-spinner mx-auto"></div>
            <p class="mt-3 text-gray-500">Caricamento...</p>
        </div>

        <!-- Griglia immagini - modificata per 3 colonne -->
        <div id="imageGrid" class="grid grid-cols-3 gap-4"></div>

        <!-- Stato vuoto -->
        <div id="emptyState" class="hidden text-center mt-20">
            <svg class="w-20 h-20 mx-auto mb-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            <h3 class="text-xl font-medium text-gray-900">Nessuna foto disponibile</h3>
            <p class="mt-3 text-gray-500">Inizia a catturare un outfit accattivante, scala le classifiche</p>
        </div>
    </div>

    <!-- Modale immagine -->
    <div id="imageModal" class="fixed inset-0 flex items-center justify-center z-50 hidden bg-black bg-opacity-90">
        <img id="modalImage" src="" alt="Immagine ingrandita" class="max-h-[80vh] max-w-[80vw] rounded transition-transform duration-300">
    </div>

    <script>
        // Funzione per gestire l'apertura e chiusura della modale
        function toggleModal(imageUrl = null) {
            const modal = document.getElementById('imageModal');
            const modalImage = document.getElementById('modalImage');
            
            if (modal.style.display === 'flex') {
                // Chiudi modale
                modal.style.display = 'none';
                modalImage.src = '';
            } else if (imageUrl) {
                // Apri modale con l'immagine
                modal.style.display = 'flex';
                modalImage.src = imageUrl;
            }
        }

        async function fetchProfileWithImages(email) {
            try {
                const response = await fetch(`/profileInformation?email=${encodeURIComponent(email)}`, { method: 'GET' });
                if (!response.ok) throw new Error('Failed to load profile');
                return await response.json();
            } catch (error) {
                console.error('Error:', error);
                throw error;
            }
        }

        function createImageElement(image) {
            const div = document.createElement('div');
            div.className = 'grid-item';
            
            const img = document.createElement('img');
            img.src = image.url;
            img.alt = 'Foto';
            img.loading = 'lazy';
            div.appendChild(img);

            // Aggiungi overlay con stella e numero di salvataggi
            const savesOverlay = document.createElement('div');
            savesOverlay.className = 'saves-overlay';
            savesOverlay.innerHTML = `
                <svg class="w-4 h-4 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
                </svg>
                <span>${image.saves}</span>
            `;
            div.appendChild(savesOverlay);

            div.onclick = () => toggleModal(image.url);
            return div;
        }

        async function initialize() {
            const urlParams = new URLSearchParams(window.location.search);
            const email = urlParams.get('email');
            if (!email) {
                console.error('Email mancante');
                return;
            }

            const loadingSpinner = document.getElementById('loadingSpinner');
            loadingSpinner.classList.remove('hidden');

            try {
                const data = await fetchProfileWithImages(email);
                document.getElementById('userName').textContent = data.userName || 'Utente sconosciuto';
                document.getElementById('points').textContent = `${data.point || 0} points`;
                document.getElementById('totalSaves').querySelector('span').textContent = `${data.save || 0} save`;

                const profileImage = document.getElementById('profileImage');
                if (data.profileImageUrl) profileImage.src = data.profileImageUrl;

                const imageGrid = document.getElementById('imageGrid');
                if (data.images && data.images.length > 0) {
                    data.images.forEach(image => {
                        imageGrid.appendChild(createImageElement(image));
                    });
                } else {
                    document.getElementById('emptyState').classList.remove('hidden');
                }
            } catch (error) {
                console.error('Error initializing:', error);
            } finally {
                loadingSpinner.classList.add('hidden');
            }

            // Aggiungi event listener alla modale per chiuderla quando si clicca su di essa
            const modal = document.getElementById('imageModal');
            modal.addEventListener('click', function() {
                toggleModal();
            });

            // Previeni che il click sull'immagine chiuda la modale
            const modalImage = document.getElementById('modalImage');
            modalImage.addEventListener('click', function(event) {
                event.stopPropagation();
            });
        }

        document.addEventListener('DOMContentLoaded', initialize);
    </script>
</body>
</html>
    """

    return render_template_string(html_template)


@app.route('/assistance', methods=['GET'])
def assistance():
    html_template = """
<!DOCTYPE html>
<html lang="it">
<head>
    <title>Form di Contatto</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.jsdelivr.net/npm/emailjs-com@3/dist/email.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #4a6fa5;
            --hover-color: #375785;
            --bg-color: #f9f9fb;
            --card-bg: #ffffff;
            --text-color: #333333;
            --error-color: #e74c3c;
            --success-color: #2ecc71;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            background-color: var(--card-bg);
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 500px;
            padding: 30px;
        }
        
        h2 {
            color: var(--primary-color);
            margin-bottom: 20px;
            text-align: center;
            font-size: 28px;
            font-weight: 600;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            font-weight: 500;
            margin-bottom: 6px;
            color: var(--text-color);
        }
        
        textarea, 
        input[type="email"] {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        textarea {
            min-height: 120px;
            resize: vertical;
        }
        
        textarea:focus, 
        input[type="email"]:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(74, 111, 165, 0.2);
        }
        
        button {
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 5px;
            padding: 12px 25px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            width: 100%;
            transition: background-color 0.3s, transform 0.1s;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
        }
        
        button:hover {
            background-color: var(--hover-color);
        }
        
        button:active {
            transform: scale(0.98);
        }
        
        #message {
            text-align: center;
            margin-top: 15px;
            padding: 10px;
            border-radius: 5px;
            font-weight: 500;
            transition: all 0.3s;
            display: none;
        }
        
        .success {
            background-color: rgba(46, 204, 113, 0.2);
            color: var(--success-color);
            display: block !important;
        }
        
        .error {
            background-color: rgba(231, 76, 60, 0.2);
            color: var(--error-color);
            display: block !important;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 0.8s linear infinite;
            margin-right: 10px;
            display: none;
        }
        
        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }
        
        .required {
            color: var(--error-color);
        }
        
        .footer {
            text-align: center;
            font-size: 12px;
            color: #888;
            margin-top: 20px;
        }
        
        @media (max-width: 576px) {
            .container {
                padding: 20px;
            }
            
            h2 {
                font-size: 24px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h2><i class="fas fa-paper-plane"></i> Invia la tua domanda</h2>
        <form id="contactForm">
            <div class="form-group">
                <label for="domanda">La tua domanda <span class="required">*</span></label>
                <textarea id="domanda" name="domanda" placeholder="Scrivi qui la tua domanda..." required></textarea>
            </div>
            
            <div class="form-group">
                <label for="email">La tua email <span class="required">*</span></label>
                <input type="email" id="email" name="email" placeholder="esempio@email.com" required>
            </div>
            
            <button type="submit">
                <div class="loading-spinner" id="spinner"></div>
                <span id="submitText">Invia messaggio</span>
            </button>
        </form>
        <p id="message"></p>
        <div class="footer">
            Ti risponderemo al più presto al tuo indirizzo email.
        </div>
    </div>
    
    <script>
        // Inizializza EmailJS con il tuo Public Key
        (function(){
            emailjs.init("YfKiORIJrF1lXiJnc"); 
        })();
        
        document.getElementById('contactForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Mostra spinner di caricamento
            document.getElementById('spinner').style.display = 'inline-block';
            document.getElementById('submitText').textContent = "Invio in corso...";
            
            const domanda = document.getElementById('domanda').value;
            const email = document.getElementById('email').value;
            const messageElement = document.getElementById('message');
            
            // Disabilita il pulsante durante l'invio
            const submitButton = document.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            
            // Parametri per EmailJS
            const templateParams = {
                domanda: domanda,
                from_email: email,
                to_email: 'giorgiomartucci02@gmail.com' 
            };
            
            emailjs.send('service_vwhqm7l', 'template_bf1zgou', templateParams)
                .then(function(response) {
                    messageElement.classList.add('success');
                    messageElement.classList.remove('error');
                    messageElement.innerHTML = '<i class="fas fa-check-circle"></i> Domanda inviata con successo!';
                    document.getElementById('contactForm').reset();
                    
                    // Nascondi il messaggio dopo 5 secondi
                    setTimeout(function() {
                        messageElement.style.display = 'none';
                        messageElement.classList.remove('success');
                    }, 5000);
                }, function(error) {
                    messageElement.classList.add('error');
                    messageElement.classList.remove('success');
                    messageElement.innerHTML = '<i class="fas fa-exclamation-circle"></i> Errore nell\\'invio. Riprova più tardi.';
                    console.error('Errore dettagliato:', JSON.stringify(error));
                })
                .finally(function() {
                    // Ripristina lo stato del pulsante
                    document.getElementById('spinner').style.display = 'none';
                    document.getElementById('submitText').textContent = 'Invia messaggio';
                    submitButton.disabled = false;
                });
        });
    </script>
</body>
</html>
"""
    return render_template_string(html_template)


@app.route('/infoPhoto', methods=['GET'])
@firebase_required
def get_photo_info():
    try:
        id_photo=request.args.get("id_photo") 

        entries = info.query.filter_by(idPhoto=id_photo).all()
        
        if not entries:
            return jsonify({
                'success': False,
                'message': 'Nessuna informazione trovata per questo foto'
            }), 404
        
        result = [{
            'type': entry.type,
            'brand': entry.brand,
            'model': entry.model,
            'feedback': entry.feedback
        } for entry in entries]
        
        return jsonify({
            'success': True,
            'data': result
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Errore nel recupero delle informazioni: {str(e)}'
        }), 500

def validate_field(field_name, field_value):
    if profanity.contains_profanity(field_value): 
        return f'Il campo {field_name} contiene contenuti potenzialmente inappropriati'
    return None


@app.route('/uploadInfo', methods=['POST'])
def upload_details():
    try:
        required_fields = ['id', 'brand', 'type', 'model', 'feedback']
        if not all(field in request.form for field in required_fields):
            return jsonify({
                'success': False,
                'message': 'Mancano dei campi richiesti'
            }), 400

       
        new_device_info = info(
            idPhoto=int(request.form.get('id')),
            type=request.form.get('type', ''),
            brand=request.form.get('brand', ''),
            model=request.form.get('model', ''),
            feedback=request.form.get('feedback', '')
        )

        db.session.add(new_device_info)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Informazioni salvate con successo'
        }), 200

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Errore durante il salvataggio: {str(e)}'
        }), 500

@app.route('/salvePhoto', methods=['POST'])
@firebase_required
def salvePhoto():
    try:
        email = request.user.get("email")
        id_photo = request.args.get("id_photo")
        
        if not email or not id_photo:
            return jsonify({
                "success": False,
                "message": "Email e ID foto sono richiesti"
            }), 400

        try:
            id_photo = int(id_photo)
        except ValueError:
            return jsonify({
                "success": False,
                "message": "ID foto deve essere un numero"
            }), 400

      
        photo_exists = FileRecord.query.filter_by(id=id_photo).first()
        if not photo_exists:
            return jsonify({
                "success": False,
                "message": "La foto richiesta non esiste"
            }), 404
      
      
        existing_record = FileSave.query.filter_by(
            emailUser=email,
            idPhoto=id_photo
        ).first()
        
        if existing_record:
            return jsonify({
                "success": False,
                "message": "Hai già salvato questa foto",
                "alreadySaved": True
            }), 403

       
        new_file = FileSave(
            emailUser=email,
            idPhoto=id_photo
        )

        db.session.add(new_file)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "Foto salvata con successo",
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({
            "success": False,
            "message": f"Errore durante il salvataggio: {str(e)}"
        }), 500

@app.route('/getUserPhotos', methods=['GET'])
@firebase_required
def getUserPhotos():
    try:
        email = request.user.get("email")

        if not email:
            return jsonify({
                "success": False,
                "message": "Email non disponibile"
            }), 400

        saved_photos = FileSave.query.filter_by(emailUser=email).all()

        if not saved_photos:
            return jsonify({
                "success": True,
                "message": f"Nessuna foto salvata per l'utente {email}",
                "data": []
            }), 200

        photo_counts = Counter([saved.idPhoto for saved in saved_photos])

        photos = FileRecord.query.filter(FileRecord.id.in_(photo_counts.keys())).all()

        photos_data = []
        for photo in photos:
            photos_data.append({
                "id": photo.id,
                "filename": photo.filename,
                "file_url": photo.file_url,
                "point": photo_counts.get(photo.id, 0) 
            })

        return jsonify({
            "success": True,
            "message": f"Trovate {len(photos_data)} foto salvate per l'utente {email}",
            "data": photos_data
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Errore durante il recupero delle foto: {str(e)}"
        }), 500

@app.route('/delete_photo_save_id', methods=['POST'])
@firebase_required
def delete_photo_save_id():
    try:

        email = request.user.get("email")
        photo_id = request.json.get('image_id')
        if not photo_id:
            return jsonify({'error': 'ID della foto mancante'}), 400

        FileSave.query.filter_by(idPhoto=photo_id, emailUser=email).delete()
        
        db.session.flush()
        
        db.session.commit()
    
        
    
        return jsonify({'message':"ok"}), 200


    except Exception as e:
        return jsonify({'error': 'Errore generico', 'details': str(e)}), 500


@app.route('/update-username', methods=['POST'])
@firebase_required
def update_username():
    data = request.json
    email = request.user.get("email")
    new_username = data.get('newUserName')
    
    if not email or not new_username:
        return jsonify({"error": "emailUser and newUserName are required"}), 400

    user = UserAccount.query.filter_by(emailUser=email).first()

    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    user.userName = new_username
    db.session.commit()
    
    return jsonify({"message": "Username updated successfully", "newUserName": user.userName})

@app.route('/search', methods=['POST'])
def search_user():

    email = request.form.get('email')
    
    if not email :
        return jsonify({'success': False, 'message': 'Email and username are required'}), 400
    

    user = UserAccount.query.filter_by(emailUser=email).first()
    
    if user:
        return jsonify({'success': True, 'message': 'User found'}), 200
    else:
        return jsonify({'success': False, 'message': 'Account non presente'}), 404


@app.route('/report', methods=['POST'])
@firebase_required
def report():
    try:
        email = request.user.get("email")
        if not email:
            return jsonify({"error": "email is required"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "request body must be JSON"}), 400

        index = data.get('index')
        if not index:
            return jsonify({"error": "index is required"}), 400
        try:
            id_photo = int(index)  
        except ValueError:
            return jsonify({"error": "index must be a valid integer"}), 400
        
        image = data.get('image')
        if not image:
            return jsonify({"error": "image is required"}), 400
       

        timestamp = data.get('timestamp')
        if not timestamp :
            return jsonify({"error": "timestamp "}), 400

        new_report = Report( 
            emailUser=email,
            idPhoto=id_photo,
            file_url=image,
            time_stamp=timestamp
        )

        db.session.add(new_report)
        db.session.commit()

        return jsonify({'message': "ok"}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host = 'localhost', port = 8080, debug = True)    