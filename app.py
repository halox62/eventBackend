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


#psql -U postgres

#load_dotenv('/Users/giorgiomartucci/Documents/OutfitApp/key.env')

#FIREBASE_PUBLIC_KEYS_URL = os.getenv("FIREBASE_PUBLIC_KEYS_URL")
#FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")


FIREBASE_PUBLIC_KEYS_URL = os.getenv("FIREBASE_PUBLIC_KEYS_URL")
FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")


app = Flask(__name__)

CORS(app) 




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



def update_event_rankings():
    with app.app_context():
        events = Event.query.filter(
            #calcolare un evento una sola volta
            or_(
                Event.endDate > datetime.now().date(),
                and_(
                    Event.endDate == datetime.now().date(),
                    Event.endTime >= datetime.now().time()
                )
            )
        ).all()
        for event in events:
            print(f"Processing event: {event.eventCode}")
            
            photos = FileRecord.query.filter_by(code=event.eventCode).all()
            sorted_photos = sorted(photos, key=lambda x: x.likes, reverse=True)
            
            for index, photo in enumerate(sorted_photos):
                user = UserAccount.query.filter_by(emailUser=photo.emailUser).first()
                if user:
                    #bool status= EventSubscibe.query.filter_by(emailUser=user.emailUser, position="true")
                    score_multiplier = 100 - index if index < 100 else 1
                    event_points = score_multiplier * photo.likes
                    user.point += event_points
                    print(f"Updated {user.emailUser} score by {event_points} points for event {event.eventCode}")
                    apply_penalty(user, event_points)

            db.session.commit()

        print("Event ranking update and penalty calculation complete.")

def apply_penalty(user, event_points):
    # Soglia di prestazione minima come percentuale del punteggio totale
    performance_threshold = 0.1  # 10% del punteggio totale
    min_required_points = user.point * performance_threshold

    if event_points < min_required_points:
        penalty_points = int((min_required_points - event_points) * 0.5)  # Penalità del 50% dei punti mancanti
        user.point -= penalty_points
        print(f"Applied penalty of {penalty_points} to {user.emailUser} due to low event performance.")

scheduler = BackgroundScheduler()
scheduler.add_job(update_event_rankings, 'cron', hour=0, minute=0)
scheduler.start()
  
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

# Modello per gli utenti
class UserAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emailUser = db.Column(db.String(120), unique=True, nullable=False)
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
    """
    Aggiorna i ranking degli eventi terminati e calcola i punti finali per gli utenti
    basandosi sulle foto caricate e i loro like.
    """
    with app.app_context(): 
        try:
            # Ottieni solo gli eventi che sono terminati
            current_datetime = datetime.now()
            completed_events = Event.query.filter(
                or_(
                    Event.endDate < current_datetime.date(),
                    and_(
                        Event.endDate == current_datetime.date(),
                        Event.endTime < current_datetime.time()
                    )
                )
            ).all()
            
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
                    print(f"No subscribed users found for event {event.eventCode}")
                    continue
                
                # Crea un set di email degli utenti iscritti per ricerca veloce
                subscribed_emails = {sub.emailUser for sub in subscribed_users}
                
                # Ottieni e processa le foto solo degli utenti iscritti
                process_event_photos(event, subscribed_emails)
                
            db.session.commit()
            print("Completed events ranking update finished")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during ranking update: {str(e)}")
            raise

def process_event_photos(event, subscribed_emails: set):
    """
    Processa le foto per un evento terminato, considerando solo gli utenti iscritti.
    """
    # Ottieni le foto con il conteggio dei like solo per gli utenti iscritti
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
        print(f"No photos found for completed event {event.eventCode}")
        return
    
    # Ordina le foto per numero di like
    sorted_photos = sorted(photos_with_likes, key=lambda x: x.likes_count, reverse=True)
    
    # Processa ogni foto e aggiorna i punti
    for index, (photo, likes_count) in enumerate(sorted_photos):
        update_user_points(photo, index, likes_count)

def update_user_points(photo, index: int, likes_count: int):
    """
    Aggiorna i punti dell'utente basandosi sulla performance della sua foto.
    """
    user = UserAccount.query.filter_by(emailUser=photo.emailUser).first()
    if not user:
        print(f"User not found for email: {photo.emailUser}")
        return
    
    # Calcola i punti
    score_multiplier = calculate_multiplier(index)
    event_points = score_multiplier * likes_count
    
    # Converti i punti attuali da string a int
    current_points = int(user.point) if user.point and user.point.isdigit() else 0
    
    # Aggiorna i punti dell'utente
    user.point = str(current_points + event_points)
    print(f"Updated {user.emailUser} score by {event_points} points")
    
    # Aggiorna i punti della foto
    photo.point = str(event_points)
    
    # Applica penalità se necessario
    apply_penalty(user, event_points)

def calculate_multiplier(index: int) -> int:
    """
    Calcola il moltiplicatore di punteggio basato sulla posizione.
    """
    return 100 - index if index < 100 else 1

def apply_penalty(user, event_points: int):
    """
    Applica una penalità se la performance è sotto la soglia minima.
    """
    PERFORMANCE_THRESHOLD = 0.1  # 10% del punteggio totale
    PENALTY_RATE = 0.5  # 50% dei punti mancanti
    
    current_points = int(user.point) if user.point and user.point.isdigit() else 0
    min_required_points = current_points * PERFORMANCE_THRESHOLD
    
    if event_points < min_required_points:
        penalty_points = int((min_required_points - event_points) * PENALTY_RATE)
        new_points = max(0, current_points - penalty_points)  # Evita punti negativi
        user.point = str(new_points)
        print(f"Applied penalty of {penalty_points} points")

scheduler = BackgroundScheduler()
scheduler.add_job(update_event_rankings, 'cron', hour=0, minute=0)
scheduler.start()



@app.route('/')
def healthcheck():
    return 'OK', 200

# Endpoint per caricare l'immagine
@app.route('/upload', methods=['POST'])
@firebase_required
def upload_image():
    try:
        file = request.files.get('file') 
        email = request.user.get("email")

        user = UserAccount.query.filter_by(emailUser=email).first()
        username = user.userName

        if file:
            # Carica il file su Firebase
            bucket = storage.bucket()
            blob = bucket.blob(f'images/{email}/{file.filename}')
            blob.upload_from_file(file)

            blob.make_public() 

            # Ottieni l'URL dell'immagine
            file_url = blob.public_url

            # Salva i metadati nel database
            new_file = FileRecord(userName=username,emailUser=email, filename=file.filename, file_url=file_url, code='null',  point="0")
            db.session.add(new_file)
            db.session.commit()

            return jsonify({'file_url': file_url}), 200
        else:
            return jsonify({'error': 'No file uploaded'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')

    access_token = create_access_token(identity={'email': email})

    return jsonify(access_token=access_token)


@app.route('/register', methods=['POST'])
def register():
    try:
        if 'profileImage' not in request.files or 'email' not in request.form or 'userName' not in request.form:
            return jsonify({"error": "Missing data or image"}), 400
        
        email = request.form['email']
        userName = request.form['userName']
        profileImage = request.files['profileImage']

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

        access_token = create_access_token(identity={'email': email})

        return jsonify(access_token=access_token), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route('/profileInformation', methods=['GET'])
def profile_with_images():
    # Estrai l'email dai parametri della query string
    email = request.args.get("email")

    if not email:
        return jsonify({"error": "Email not provided"}), 400


    user = UserAccount.query.filter_by(emailUser=email).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404


    images = []
    blobs = bucket.list_blobs(prefix=f'images/{email}/')  

    for blob in blobs:
        blob.make_public() 
        images.append(blob.public_url)

    return jsonify({
        "userName": user.userName,
        "profileImageUrl": user.profileImageUrl,
        "point": user.point,
        "images": images
    }), 200
    

@app.route('/profile', methods=['POST'])
@firebase_required
def get_profile():

    email = request.user.get("email")

    if not email:
        return jsonify({"error": "Email not provided"}), 400

    user = UserAccount.query.filter_by(emailUser=email).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404
    

    return jsonify({
        "userName": user.userName,
        "profileImageUrl": user.profileImageUrl,
        "point":user.point
    }), 200


@app.route('/getImage', methods=['POST'])
@firebase_required
def get_Image():
   
    email = request.user.get("email")

   
    if not email:
        return jsonify({"error": "Email not provided"}), 400

    
    images = []
    blobs = bucket.list_blobs(prefix=f'images/{email}/')  

   
    for blob in blobs:
        blob.make_public() 
        images.append(blob.public_url)
    
    return jsonify({"images": images}), 200

@app.route('/createEvent', methods=['POST'])
@firebase_required
def createEvent():
    try:

        email = request.user.get("email")
        eventName = request.form['eventName']
        eventCode = request.form['eventCode']
        eventDate = request.form['eventDate']
        endDate = request.form['endDate']
        endTime = request.form['endTime']
        latitudine = request.form['latitudine']
        longitude = request.form['longitude']
        create = request.form['create']


      
        if not all([email, eventCode, eventDate, endDate, endTime, longitude, latitudine, create]):
            return jsonify({"error": "One or more fields are missing"}), 400

       
        try:
            event_date = datetime.strptime(eventDate, '%Y-%m-%d').date()
            end_date = datetime.strptime(endDate, '%Y-%m-%d').date()
            end_time = datetime.strptime(endTime, '%H:%M').time()
        except ValueError as ve:
            return jsonify({"error": f"Date or time format error: {str(ve)}"}), 400
        
       
        new_event = Event(
            eventName=eventName,
            emailUser=email,
            eventCode=eventCode,
            eventDate=event_date,
            endDate=end_date,  
            endTime=end_time,  
            longitude=longitude,
            latitudine=latitudine,
            create=create
        )

       
        db.session.add(new_event)
        db.session.commit()

        return jsonify({"message": "Event created successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 400 

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
    



@app.route('/getEventCode', methods=['GET'])
@firebase_required
def getEventCode():
    try:
        email = request.user.get("email")
        
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        


       
        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()
        subscribed_event_codes = [sub.eventCode for sub in subscribed_events]

        if not subscribed_event_codes:
            return jsonify({"message": "No subscribed events found for this email"}), 404

      
        ongoing_events = Event.query.filter(
            Event.eventCode.in_(subscribed_event_codes),
            or_(
                # Caso 1: la data di fine è successiva o uguale a oggi
                Event.endDate > datetime.now().date(),
                # Caso 2: la data di fine è oggi e l'orario di fine è futuro o presente
                and_(
                    Event.endDate == datetime.now().date(),
                    Event.endTime >= datetime.now().time()
                )
            )
        ).all()

        # Se non ci sono eventi attivi
        if not ongoing_events:
            return jsonify({"event_codes": "null"}), 400

        return jsonify({"event_codes": [event.eventCode for event in ongoing_events]}), 200

    except Exception as e:
        print(str(e))
        return jsonify({"error": str(e)}), 500
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


    try:

        
        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()
        create_events=Event.query.filter_by(emailUser=email, create="yes").all()
        event_codes = [sub.eventCode for sub in subscribed_events] + [evn.eventCode for evn in create_events]


       
        events = Event.query.filter(Event.eventCode.in_(event_codes),and_(Event.eventDate == event_date_str,Event.emailUser==email)).all()

        if not events:
            return jsonify({'message': 'Nessun evento trovato per questa data'}), 404

       
        events_list = []
        for event in events:
            events_list.append({
                'id': event.id,
                'eventName': event.eventName,
                'emailUser': event.emailUser,
                'eventCode': event.eventCode,
                'eventDate': event.eventDate.strftime('%Y-%m-%d'),
                'endDate': event.endDate.strftime('%Y-%m-%d'),
                'endTime': event.endTime.strftime('%H:%M:%S'),
                'longitude': event.longitude,
                'latitudine': event.latitudine
            })

      
        return jsonify({'events': events_list}), 200

    except ValueError:
       
        return jsonify({'message': 'Formato della data non valido. Usa YYYY-MM-DD.'}), 400
    

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
            position="false" 
        )

        db.session.add(new_subscription)
        db.session.commit()
        
        return jsonify({'message': 'Successfully registered to event'}), 200

    except Exception as e:
        db.session.rollback()  
        return jsonify({'message': 'Internal server error'}), 500
    

@app.route('/uploadEventImage', methods=['POST'])#query per caricare una foto per un evento
@firebase_required
def uploadEventImage():
    try:
        email = request.user.get("email")
        code = request.form['eventCode']
        file = request.files.get('image')

        user = UserAccount.query.filter_by(emailUser=email).first()
        username = user.userName
        
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        
        if file:
            
            bucket = storage.bucket()
            blob = bucket.blob(f'images/{email}/{file.filename}')
            blob.upload_from_file(file)

            blob.make_public() 

           
            file_url = blob.public_url

           
            new_file = FileRecord(userName=username, emailUser=email, filename=file.filename, file_url=file_url, code=code, point="0")
            db.session.add(new_file)
            db.session.commit()

            return jsonify({'file_url': file_url}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

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


        name_res = {"name": name} 


        if not name_res:
            return jsonify({"message": "No name for this event code."}), 404
        
        
        return jsonify(name_res), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400

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

        profiles = [UserAccount.query.filter_by(emailUser=email).first() for email in emails]

        profiles = [profile for profile in profiles if profile]

        image_profiles = [{"image_path": profile.profileImageUrl} for profile in profiles]

        if not image_profiles:
            return jsonify({"message": "No images found for this event code."}), 404

        return jsonify(image_profiles), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400



@app.route('/photoByCode', methods=['POST'])  # Query che ritorna le foto di un evento per un determinato codice
@firebase_required
def photoByCode():
    try:
        data = request.json
        email = request.user.get("email")
        code = data.get('code')

        if not code:
            return jsonify({"error": "Event code not provided"}), 400
        
        images = FileRecord.query.filter_by(code=code, emailUser=email).all()

        image_links = [{"image_path": img.file_url, "likes": int(img.point),"name": img.userName} for img in images]

        if not image_links:
            return jsonify({"message": "No images found for this event code."}), 404
        
        
        return jsonify(image_links), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

    


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

       
        liked_photos = db.session.query(LikePhoto, FileRecord) \
            .join(FileRecord, LikePhoto.file_id == FileRecord.id) \
            .filter(LikePhoto.emailUser == email) \
            .all()

        image_links = [{"image_path": record.file_url, "likes": record.point} for _, record in liked_photos]



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

        ranked_photos = FileRecord.query.filter_by(code=event_code).order_by(FileRecord.point.desc()).all()

        print(ranked_photos)

        photos = []
        for photo in ranked_photos:
            photos.append({
                'image_path': photo.file_url,
                'likes': int(photo.point),
            })

        return jsonify({'photos': photos}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

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
        top_users = (
            db.session.query(UserAccount)
            .order_by(UserAccount.point.desc())
            .limit(100)
            .all()
        )

        if not top_users:
            return jsonify({"message": "No users found"}), 404

        scoreboard = []
        for user in top_users:
            scoreboard.append({
                "id": user.id,
                "emailUser": user.emailUser,
                "userName": user.userName,
                "profileImageUrl": user.profileImageUrl,
                "point": user.point
            })

        return jsonify({"scoreboard": scoreboard}), 200

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
        }

        body {
            background-color: #fafafa;
            display: block; /* Cambiato da flex a block */
            padding: 20px 0; /* Spazio dal top */
            min-height: 100vh;
        }

        .profile-card {
            background-color: white;
            border-radius: 16px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }

        .grid-item {
            position: relative;
            aspect-ratio: 1;
            border-radius: 8px;
            overflow: hidden;
            background-color: var(--surface-variant);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: transform 0.3s ease; /* Animazione al clic */
        }

        .grid-item img {
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
        }

        #imageModal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
            display: none; /* Modale nascosta di default */
            align-items: center;
            justify-content: center;
        }

        #imageModal img {
            max-height: 80vh;
            max-width: 80vw;
            object-fit: contain;
            border-radius: 8px;
            transition: transform 0.3s ease;
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
            0% {
                transform: rotate(0deg);
            }
            100% {
                transform: rotate(360deg);
            }
        }
    </style>
</head>
<body>
    <div class="main-container px-4">
        <!-- Profilo utente -->
        <div class="profile-card p-6 mb-6">
            <div class="flex items-center space-x-6">
                <div class="flex-shrink-0">
                    <img id="profileImage" 
                         class="w-24 h-24 rounded-full object-cover shadow-md border-2 border-white"
                         src=""
                         alt="Immagine profilo"
                         onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 24 24%22><path fill=%22%23666%22 d=%22M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8zM6 12a6 6 0 1 1 12 0v1H6v-1z%22/></svg>'">
                </div>
                <div>
                    <h1 id="userName" class="text-2xl font-bold mb-2">Utente</h1>
                    <div class="points-badge bg-green-600 text-white py-2 px-4 rounded-full font-semibold">
                        <span id="points">0 punti</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Spinner di caricamento -->
        <div id="loadingSpinner" class="text-center hidden">
            <div class="loading-spinner mx-auto"></div>
            <p class="mt-3 text-gray-500">Caricamento...</p>
        </div>

        <!-- Griglia immagini -->
        <div id="imageGrid" class="grid grid-cols-4 gap-4"></div>

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
    <div id="imageModal" class="fixed inset-0 flex items-center justify-center z-50 hidden bg-black bg-opacity-90" onclick="toggleModal()">
        <img id="modalImage" src="" alt="Immagine ingrandita" class="max-h-[80vh] max-w-[80vw] rounded transition-transform duration-300" onclick="event.stopPropagation();">
    </div>

    <script>
        function toggleModal(imageUrl = null) {
            const modal = document.getElementById('imageModal');
            const modalImage = document.getElementById('modalImage');
            
            if (modal.classList.contains('hidden')) {
                // Mostra la modale
                modal.classList.remove('hidden');
                modalImage.src = imageUrl;
            } else {
                // Nasconde la modale
                modal.classList.add('hidden');
                modalImage.src = ''; // Ripristina il contenuto
            }
        }
    </script>

    <script>
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

        function createImageElement(imageUrl) {
            const div = document.createElement('div');
            div.className = 'grid-item';
            const img = document.createElement('img');
            img.src = imageUrl;
            img.alt = 'Foto';
            img.onclick = () => toggleModal(imageUrl);
            div.appendChild(img);
            return div;
        }

        function toggleModal(imageUrl) {
            const modal = document.getElementById('imageModal');
            const modalImage = document.getElementById('modalImage');
            if (modal.style.display === 'flex') {
                modal.style.display = 'none';
                modalImage.src = '';
            } else {
                modal.style.display = 'flex';
                modalImage.src = imageUrl;
            }
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
                document.getElementById('points').textContent = `${data.point || 0} punti`;

                const profileImage = document.getElementById('profileImage');
                if (data.profileImageUrl) profileImage.src = data.profileImageUrl;

                const imageGrid = document.getElementById('imageGrid');
                if (data.images && data.images.length > 0) {
                    data.images.forEach(imageUrl => {
                        imageGrid.appendChild(createImageElement(imageUrl));
                    });
                } else {
                    document.getElementById('emptyState').classList.remove('hidden');
                }
            } catch (error) {
                console.error('Error initializing:', error);
            } finally {
                loadingSpinner.classList.add('hidden');
            }
        }

        initialize();
    </script>
</body>
</html>
    """

    return render_template_string(html_template)

if __name__ == '__main__':
    app.run(host = 'localhost', port = 8080, debug = True)    