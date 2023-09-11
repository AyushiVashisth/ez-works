from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os
from werkzeug.utils import secure_filename
import pymongo
import bcrypt
import datetime
from bson import ObjectId
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configure Flask JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
jwt = JWTManager(app)

# Configure MongoDB connection
client = pymongo.MongoClient(os.environ.get('MONGODB_URI'))
db = client["file_sharing_db"]
users_collection = db["users"]
files_collection = db["files"]

# Configure file upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Register a new Ops User
@app.route('/ops/register', methods=['POST'])
def ops_register():
    data = request.get_json()
    email = data['email']
    password = data['password']

    # Check if the user already exists
    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert the user into the database
    user_id = users_collection.insert_one({
        "email": email,
        "password": hashed_password,
        "role": "ops"
    }).inserted_id

    return jsonify({"message": "Ops User registered successfully", "user_id": str(user_id)}), 201

# Ops User login
@app.route('/ops/login', methods=['POST'])
def ops_login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = users_collection.find_one({"email": email, "role": "ops"})

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401
    
# Upload file by Ops User
@app.route('/ops/upload-file', methods=['POST'])
@jwt_required()
def upload_file():
    current_user_id = get_jwt_identity()
    current_user = users_collection.find_one({"_id": ObjectId(current_user_id)})

    if current_user and current_user['role'] == 'ops':
        if 'file' not in request.files:
            return jsonify({'message': 'No file part'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            # Save file details to the database
            file_id = files_collection.insert_one({
                "filename": filename,
                "uploaded_by": current_user['_id'],
                "upload_date": datetime.datetime.now()
            }).inserted_id

            return jsonify({'message': 'File uploaded successfully', 'file_id': str(file_id)}), 201
        else:
            return jsonify({'message': 'Invalid file type'}), 400
    else:
        return jsonify({'message': 'Unauthorized'}), 401

# Client User signup
@app.route('/clients/signup', methods=['POST'])
def client_signup():
    data = request.get_json()
    email = data['email']

    # Check if the user already exists
    if users_collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 400

    # Generate a unique verification token (for simplicity, use the user's ObjectId)
    verification_token = str(ObjectId())

    # Insert the user into the database with an unverified email
    user_id = users_collection.insert_one({
        "email": email,
        "verification_token": verification_token,
        "verified": False,
        "role": "client"
    }).inserted_id

    # Send a verification email to the user
    send_verification_email(email, verification_token)

    return jsonify({"message": "Client User registered successfully"}), 201

# Email verification for Client Users
@app.route('/clients/verify-email/<verification_token>', methods=['GET'])
def verify_email(verification_token):
    user = users_collection.find_one({"verification_token": verification_token})

    if user:
        # Mark the email as verified
        users_collection.update_one({"_id": user["_id"]}, {"$set": {"verified": True}})
        return jsonify({"message": "Email verification successful"}), 200
    else:
        return jsonify({"message": "Invalid verification token"}), 400

# Client User login
@app.route('/clients/login', methods=['POST'])
def client_login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = users_collection.find_one({"email": email, "role": "client", "verified": True})

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# Generate a secure download link for a file
@app.route('/clients/download-file/<file_id>', methods=['GET'])
@jwt_required()
def generate_download_link(file_id):
    current_user_id = get_jwt_identity()
    current_user = users_collection.find_one({"_id": ObjectId(current_user_id), "role": "client"})

    if current_user:
        file = files_collection.find_one({"_id": ObjectId(file_id)})

        if file:
            # Generate a secure download link (for simplicity, use file_id)
            download_link = f"/download-file/{file_id}"
            return jsonify({'download-link': download_link, 'message': 'success'}), 200
        else:
            return jsonify({'message': 'File not found'}), 404
    else:
        return jsonify({'message': 'Unauthorized'}), 401

# Serve the file for download
@app.route('/download-file/<file_id>', methods=['GET'])
@jwt_required()
def download_file(file_id):
    current_user_id = get_jwt_identity()
    current_user = users_collection.find_one({"_id": ObjectId(current_user_id), "role": "client"})

    if current_user:
        file = files_collection.find_one({"_id": ObjectId(file_id)})

        if file:
            # Retrieve the file from the server (assuming files are stored in the UPLOAD_FOLDER)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file['filename'])
            
            if os.path.exists(file_path):
                return send_file(file_path, as_attachment=True)
            else:
                return jsonify({'message': 'File not found on the server'}), 404
        else:
            return jsonify({'message': 'File not found'}), 404
    else:
        return jsonify({'message': 'Unauthorized'}), 401

# Send a verification email to the client user
def send_verification_email(email, verification_token):
    message = Mail(
        from_email='your_email@example.com',
        to_emails=email,
        subject='Email Verification for File Sharing System',
        html_content=f'<p>Click the following link to verify your email: <a href="/clients/verify-email/{verification_token}">Verify Email</a></p>')
    
    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        sg.send(message)
    except Exception as e:
        print(str(e))

if __name__ == '__main__':
    app.run(debug=True, port=5000) 

