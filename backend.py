from operator import and_, or_
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

#psql -U postgres
#celery -A backend.celery worker --loglevel=debug

app = Flask(__name__)

CORS(app) 


def update_event_rankings():
    print("hello")
    with app.app_context():
        events = Event.query.filter(
                and_(
                    Event.endDate <= datetime.now(),
                    Event.endTime <= datetime.now().time()
                )
            ).all()
        for event in events:
            print(f"Processing event: {event.eventCode}")
            
            photos = FileRecord.query.filter_by(code=event.eventCode).all()
            sorted_photos = sorted(photos, key=lambda x: x.likes, reverse=True)
            
            for index, photo in enumerate(sorted_photos):
                user = UserAccount.query.filter_by(emailUser=photo.emailUser).first()
                if user:
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
scheduler.add_job(update_event_rankings, 'cron', hour=17, minute=46)
scheduler.start()
  
# Configurazione del database PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Giorgio02@localhost/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inizializza il database
db = SQLAlchemy(app)

# Modello per il file caricato
class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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

# Inizializza Firebase Admin SDK con il file di credenziali
cred = credentials.Certificate("/Users/giorgiomartucci/Documents/OutfitApp/outfitsocial-a6124-firebase-adminsdk-tl0t6-7632eff8d4.json")
firebase_admin.initialize_app(cred, {
    'storageBucket': 'outfitsocial-a6124.appspot.com'  
})

bucket = storage.bucket()

# Endpoint per caricare l'immagine
@app.route('/upload', methods=['POST'])
def upload_image():
    try:
        file = request.files.get('file') 
        email = request.form.get('email')

        if file:
            # Carica il file su Firebase
            bucket = storage.bucket()
            blob = bucket.blob(f'images/{email}/{file.filename}')
            blob.upload_from_file(file)

            blob.make_public() 

            # Ottieni l'URL dell'immagine
            file_url = blob.public_url

            # Salva i metadati nel database
            new_file = FileRecord(emailUser=email, filename=file.filename, file_url=file_url, code='null',  point="0")
            db.session.add(new_file)
            db.session.commit()

            return jsonify({'file_url': file_url}), 200
        else:
            return jsonify({'error': 'No file uploaded'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        # Controlla se la richiesta contiene dati e file
        if 'profileImage' not in request.files or 'email' not in request.form or 'userName' not in request.form:
            return jsonify({"error": "Missing data or image"}), 400
        
        # Ottieni i campi dalla richiesta form-data
        email = request.form['email']
        userName = request.form['userName']
        profileImage = request.files['profileImage']

        # Verifica se l'email o il nome utente è già registrato
        existing_user = UserAccount.query.filter_by(emailUser=email).first()
        if existing_user:
            return jsonify({"error": "Email already registered"}), 400

        # Carica l'immagine su Firebase Storage
        bucket = storage.bucket()
        blob = bucket.blob(f'images/profile/{profileImage.filename}')
        blob.upload_from_file(profileImage)
        blob.make_public() 

        # Ottieni l'URL pubblico dell'immagine caricata
        profileImageUrl = blob.public_url

        # Crea un nuovo utente e salva nel database
        new_user = UserAccount(emailUser=email, userName=userName, profileImageUrl=profileImageUrl, point="0")
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User registered successfully", "imageUrl": profileImageUrl}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route('/profile', methods=['POST'])
def get_profile():
    data = request.json
    email = data.get('email')


    if not email:
        return jsonify({"error": "Email not provided"}), 400

    # A questo punto, dovresti cercare l'utente nel tuo database
    user = UserAccount.query.filter_by(emailUser=email).first()
    if user is None:
        return jsonify({"error": "User not found"}), 404
    

    # Se l'utente esiste, restituisci i dati del profilo
    return jsonify({
        "userName": user.userName,
        "profileImageUrl": user.profileImageUrl,
        "point":user.point
    }), 200


@app.route('/getImage', methods=['POST'])
def get_Image():
    # Recupera i dati dalla richiesta
    data = request.json
    email = data.get('email')

    # Controlla se l'email è stata fornita
    if not email:
        return jsonify({"error": "Email not provided"}), 400

    # Cerca tutte le immagini associate all'email
    images = []
    blobs = bucket.list_blobs(prefix=f'images/{email}/')  

    # Aggiungi ogni URL dell'immagine alla lista
    for blob in blobs:
        blob.make_public() 
        images.append(blob.public_url)

    # Se non ci sono immagini per quell'email
    if not images:
        return jsonify({"error": "No images found for this email"}), 404

    # Restituisce la lista di immagini
    return jsonify({"images": images}), 200

@app.route('/createEvent', methods=['POST'])
def createEvent():
    try:
        # Recupera i dati dalla richiesta
        email = request.form['email']
        eventCode = request.form['eventCode']
        eventDate = request.form['eventDate']
        endDate = request.form['endDate']
        endTime = request.form['endTime']
        latitudine = request.form['latitudine']
        longitude = request.form['longitude']
        create = request.form['create']


        # Controlla se i campi sono stati forniti
        if not all([email, eventCode, eventDate, endDate, endTime, longitude, latitudine, create]):
            return jsonify({"error": "One or more fields are missing"}), 400

        # Converti le stringhe delle date e degli orari in oggetti datetime
        try:
            event_date = datetime.strptime(eventDate, '%Y-%m-%d').date()
            end_date = datetime.strptime(endDate, '%Y-%m-%d').date()
            end_time = datetime.strptime(endTime, '%H:%M').time()
        except ValueError as ve:
            return jsonify({"error": f"Date or time format error: {str(ve)}"}), 400
        
        # Crea un nuovo evento con i dettagli forniti
        new_event = Event(
            emailUser=email,
            eventCode=eventCode,
            eventDate=event_date,
            endDate=end_date,  
            endTime=end_time,  
            longitude=longitude,
            latitudine=latitudine,
            create=create
        )

        # Salva l'evento nel database
        db.session.add(new_event)
        db.session.commit()

        return jsonify({"message": "Event created successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 400 

@app.route('/getCreateEvent', methods=['POST'])#query che ritorna gli eventi che sono stati creati da un'email
def getCreateEvent():
    try:
        # Recupera i dati dalla richiesta
        email = request.form['email']
        
        # Controlla se l'email è stata fornita
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        
        # Query per ottenere i codici degli eventi associati all'email
        eventi = Event.query.filter_by(emailUser=email).all()

        # Se non ci sono eventi, restituisci un messaggio appropriato
        if not eventi:
            return jsonify({"message": "No events found for this email"}), 404

        # Ritorna i codici degli eventi in formato JSON
        return jsonify({"event_codes": [evento.eventCode for evento in eventi]}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    



@app.route('/getEventCode', methods=['GET'])
def getEventCode():
    try:
        email = request.args.get('email')
        
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        


        # Recupera i codici degli eventi a cui l'utente è iscritto
        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()
        subscribed_event_codes = [sub.eventCode for sub in subscribed_events]

        if not subscribed_event_codes:
            return jsonify({"message": "No subscribed events found for this email"}), 404

        # Crea un timestamp concatenando eventDate e endTime
        ongoing_events = (
            Event.query.filter(
                Event.eventCode.in_(subscribed_event_codes),
                and_(
                    Event.endDate >= datetime.now(),
                    Event.endTime >= datetime.now().time()
                )
            ).all()
        )



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
def get_event_dates():
    try:
        email = request.args.get('email') 

        # Controlla se l'email è stata fornita
        if not email:
            return jsonify({"error": "Email not provided"}), 400

        # Recupera gli eventi associati all'email
        events = Event.query.filter_by(emailUser=email , create="yes").all()

        # Estrai le date degli eventi
        event_dates = [event.eventDate.strftime('%Y-%m-%d') for event in events]
        

        return jsonify(event_dates), 200  # Restituisci le date in formato JSON
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route('/subscribeGetEventDates', methods=['GET'])#ritorna le date degli eventi dove partecipa un'email
def get_event_datesAdd():
    try:
        email = request.args.get('email')


        if not email:
            return jsonify({"error": "Email not provided"}), 400

        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()

        event_codes = [event.eventCode for event in subscribed_events]

        events = Event.query.filter(Event.eventCode.in_(event_codes)).all()

        event_dates = [event.eventDate.strftime('%Y-%m-%d') for event in events]

        return jsonify(event_dates), 200  # Restituisci le date in formato JSON
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    


@app.route('/events_by_date', methods=['POST'])
def get_events_by_date():
    # Recupera i dati dalla richiesta
    data = request.json
    email = data.get('email')
    event_date_str = data.get('date')

    try:

        # Recupera gli eventCode dalla tabella EventSubscibe associati all'email
        subscribed_events = EventSubscibe.query.filter_by(emailUser=email).all()
        create_events=Event.query.filter_by(emailUser=email, create="yes").all()
        event_codes = [sub.eventCode for sub in subscribed_events] + [evn.eventCode for evn in create_events]


        # Filtra gli eventi nella tabella Event in base ai codici e alla data
        events = Event.query.filter(Event.eventCode.in_(event_codes),and_(Event.eventDate == event_date_str,Event.emailUser==email)).all()

        if not events:
            return jsonify({'message': 'Nessun evento trovato per questa data'}), 404

        # Crea una lista di eventi da restituire come JSON
        events_list = []
        for event in events:
            events_list.append({
                'id': event.id,
                'emailUser': event.emailUser,
                'eventCode': event.eventCode,
                'eventDate': event.eventDate.strftime('%Y-%m-%d'),
                'endDate': event.endDate.strftime('%Y-%m-%d'),
                'endTime': event.endTime.strftime('%H:%M:%S'),
                'longitude': event.longitude,
                'latitudine': event.latitudine
            })

        # Restituisce i dettagli degli eventi come JSON
        return jsonify({'events': events_list}), 200

    except ValueError:
        # Gestisce errori nel formato della data
        return jsonify({'message': 'Formato della data non valido. Usa YYYY-MM-DD.'}), 400
    

@app.route('/addEvent', methods=['POST'])
def addEvent():

    data = request.json
    email = data.get('email')
    code = data.get('code')

    try:
        Subscibe = EventSubscibe(
            emailUser=email,
            eventCode=code,
            position="false"
        )

        db.session.add(Subscibe)
        db.session.commit() 
      
       
        return jsonify({'events': "ok"}), 200

    except ValueError:
        # Gestisce errori nel formato della data
        return jsonify({'message': 'Error'}), 400
    

@app.route('/uploadEventImage', methods=['POST'])#query per caricare una foto per un evento
def uploadEventImage():
    try:
        email = request.form['email']
        code = request.form['eventCode']
        file = request.files.get('image')
        
        if not email:
            return jsonify({"error": "Email not provided"}), 400
        
        if file:
            # Carica il file su Firebase
            bucket = storage.bucket()
            blob = bucket.blob(f'images/{email}/{file.filename}')
            blob.upload_from_file(file)

            blob.make_public() 

            # Ottieni l'URL dell'immagine
            file_url = blob.public_url

            # Salva i metadati nel database
            new_file = FileRecord(emailUser=email, filename=file.filename, file_url=file_url, code=code, point="0")
            db.session.add(new_file)
            db.session.commit()

            return jsonify({'file_url': file_url}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route('/photoByCode', methods=['POST'])  # Query che ritorna le foto di un evento per un determinato codice
def photoByCode():
    try:
        data = request.json
        email = data.get('email')
        code = data.get('code')

        if not code:
            return jsonify({"error": "Event code not provided"}), 400
        
        images = FileRecord.query.filter_by(code=code, emailUser=email).all()

        image_links = [{"image_path": img.file_url, "likes": int(img.point)} for img in images]

        if not image_links:
            return jsonify({"message": "No images found for this event code."}), 404
        
        
        return jsonify(image_links), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

    


@app.route('/increment_like', methods=['POST'])
def increment_like():
    try:
        data = request.get_json()
        
        image_id = data.get('photoId')
        email = data.get('email') 

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
    




@app.route('/get_like', methods=['POST'])
def get_like():
    try:
        data = request.get_json()
        
        email = data.get('email') 

       
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
def set_position_true():
    try:
        data = request.get_json()
        email = data.get('email')
        event_code = data.get('eventCode')

        # Verifica se i dati sono presenti
        if not email or not event_code:
            return jsonify({"error": "Email or event code not provided"}), 400

        # Troviamo la riga corrispondente all'utente e all'evento
        subscription = EventSubscibe.query.filter_by(emailUser=email, eventCode=event_code).first()

        # Se la sottoscrizione non esiste
        if not subscription:
            return jsonify({"error": "Subscription not found"}), 404

        # Settiamo la posizione a "true"
        subscription.position = "true"
        
        # Salviamo le modifiche nel database
        db.session.commit()

        return jsonify({"message": "Position set to true successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/get_scoreboard', methods=['GET'])
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

        # Creazione della risposta JSON con i dati richiesti
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
def get_user_ranking():
    try:
        email = request.args.get('email')

        if not email:
            return jsonify({"error": "Email is required"}), 400

        # Trova il punteggio e la posizione dell'utente
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

        # Recupera i 10 utenti sopra e 10 utenti sotto
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

        # Formatta la risposta
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
    
    
if __name__ == '__main__':
    app.run(debug=True)        