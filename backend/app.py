from flask import Flask, request, jsonify, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS  # Import CORS

from Crypto.Util.Padding import pad, unpad

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64

from pymongo import MongoClient
from bson import ObjectId
from bson import json_util

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import bcrypt
from dotenv import load_dotenv

import boto3

from authlib.integrations.flask_client import OAuth
import requests

import os
import uuid
import datetime

load_dotenv()

#assigning the ENV variables
client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
jwt_secret = os.getenv("JWT_SECRET")
mongodb_uri = os.getenv("MONGO_DB_URI")

app = Flask(__name__)

# Configuring Flask-JWT-Extended
# JWT Configuration
app.config['JWT_SECRET_KEY'] = jwt_secret  # Change this to a secure key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(days=1)

app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # Max file size (100 MB)

jwt = JWTManager(app)

# Enable CORS
CORS(app)

# MongoDB Configuration
client = MongoClient(mongodb_uri)  # MongoDB URI
db = client["SecureStorage"]  # Database name
users = db["users"]  # Collection name
files_collection = db["files"]

# Configuring OAuth with Authlib
oauth = OAuth(app)
google = oauth.register(
    'google',
    client_id=client_id,
    client_secret=client_secret,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'email'},
)

# AWS S3 Configuration
s3_client = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name="ap-south-1",  # Update with your region
)
s3_bucket_name = os.getenv("S3_BUCKET_NAME")


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def decrypt_file(encrypted_content, nonce, encrypted_key, tag):
    try:
        rsa_private_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
        aes_key = cipher_rsa.decrypt(encrypted_key)

        # Decrypt the file content using AES
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_content = cipher_aes.decrypt_and_verify(encrypted_content, tag)
        
        return decrypted_content

    except ValueError as e:
        raise ValueError(f"Decryption error: {str(e)}")
    except Exception as e:
        raise Exception(f"Unexpected error during decryption: {str(e)}")

private_key, public_key = generate_rsa_keys()

# Google OAuth Callback route
'''
@app.route('/auth/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)
    
    email = user_info.get('email')
    username = user_info.get('name')

    # Check if the user already exists in the "database"
    if email in users_db:
        jwt_token = create_access_token(identity=email)
        return jsonify(access_token=jwt_token), 200

    # If user doesn't exist, create a new user
    users_db[email] = {'username': username}
    jwt_token = create_access_token(identity=email)
    return jsonify(access_token=jwt_token), 201
'''
'''
# Google OAuth Login route
@app.route('/login/google')
def login_google():
    return google.authorize_redirect(url_for('google_callback', _external=True))
'''

# ---------------- SIGNUP ENDPOINT ----------------
@app.route("/api/signup", methods=["POST"])
def signup():
    try:
        data = request.json
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        # Check if user already exists
        if users.find_one({"email": email}):
            return jsonify({"error": "Email already registered"}), 400

        # Generate salt and hash password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Insert new user
        user = {
            "username": username,
            "email": email,
            "salt": salt.decode('utf-8'),
            "password": hashed_password.decode('utf-8'),
        }
        users.insert_one(user)

        # Generate access token
        access_token = create_access_token(identity=email)
        return jsonify({"access_token": access_token}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/google-signup', methods=['POST'])
def google_signup():
    try:
        # Extract the Google token sent by the frontend
        data = request.get_json()
        google_token = data.get('token')

        # Verify the token with Google's endpoint
        url = f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={google_token}'
        response = requests.get(url)
        user_info = response.json()

        # Check if the token is valid
        if 'error' in user_info:
            return jsonify({"error": "Invalid Google token"}), 400

        # Extract user details from the token response
        email = user_info.get('email')
        username = user_info.get('name')
        google_id = user_info.get('sub')  # Google's unique user ID

        # Check if the user already exists in MongoDB
        existing_user = users.find_one({"email": email})
        if existing_user:
            # Generate access token for existing users
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token,email=email), 200

        # If the user doesn't exist, create a new entry in MongoDB
        user = {
            "username": username,
            "email": email,
            "google_id": google_id,  # Store Google's unique user ID
            "auth_provider": "google"  # Store provider info
        }
        users.insert_one(user)

        # Generate JWT token for the new user
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token), 201

    except Exception as e:
        # Handle any errors
        return jsonify({"error": str(e)}), 500



# ---------------- LOGIN ENDPOINT ----------------
@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")
        print("Email",email,"Password",password)
        # Check if user exists
        user = users.find_one({"email": email})
        print("User",user)
        if not user:
            return jsonify({"error": "Invalid email or password"}), 401

        # Verify password with salt
        salt = user["salt"].encode('utf-8')  # Retrieve stored salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        print("Hashed Password",hashed_password.decode('utf-8'))
        print("Stored Password",user["password"])
        if hashed_password.decode('utf-8') != user["password"]:
            return jsonify({"error": "Invalid email or password"}), 401

        # Generate access token
        access_token = create_access_token(identity=email)
        return jsonify({"access_token": access_token}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Google Login endpoint
@app.route('/api/google-login', methods=['POST'])
def google_login():
    try:
        # Extract the Google token sent by the frontend
        data = request.get_json()
        google_token = data.get('token')

        # Verify the token with Google
        url = f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={google_token}'
        response = requests.get(url)
        user_info = response.json()

        # Check if the token is valid
        if 'error' in user_info:
            return jsonify({"error": "Invalid token"}), 400

        # Extract email and Google ID
        email = user_info['email']
        google_id = user_info['sub']

        # Check if the user exists in MongoDB
        user = users.find_one({"email": email})
        if user:
            # If the user exists, generate an access token
            access_token = create_access_token(identity=email)
            return jsonify(access_token=access_token), 200

        # If the user doesn't exist, create them
        username = user_info['name']
        new_user = {
            "username": username,
            "email": email,
            "google_id": google_id,
            "auth_provider": "google"
        }
        users.insert_one(new_user)

        # Generate JWT token for the new user
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token), 201

    except Exception as e:
        # Handle any errors
        return jsonify({"error": str(e)}), 500

# ---------------- VERIFY TOKEN ----------------

@app.route('/api/verify-token', methods=['GET'])
@jwt_required()
def verify_token():
    current_user = get_jwt_identity()
    return jsonify({"valid": True, "user": current_user}), 200

# ---------------- PROTECTED ENDPOINT  ----------------

# Logout route
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify(message="Successfully logged out"), 200


# File upload route
@app.route("/api/upload-file", methods=["POST"])
@jwt_required()
def upload_file():
    print("Inside Upload..")
    try:
        # Get the JWT identity (user email)
        owner_email = get_jwt_identity()
        print("Owner Email",owner_email)
        # Get files from the request
        if "files" not in request.files:
            return jsonify({"error": "No files found in request"}), 400

        files = request.files.getlist("files")
        uploaded_files = []
        print("Files",files)
        for file in files:
            # Secure the file name and generate a unique file key
            file_name = secure_filename(file.filename)
            file_key = str(uuid.uuid4()) + "_" + file_name
            file_size = file.tell()  # Get the file size
            file.seek(0)  # Reset file pointer after reading size

            aes_key = get_random_bytes(32)  # AES 256-bit key
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(file.read())
            file.seek(0)

            rsa_public_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            # Upload to S3
            # s3_client.put_object(
            #     Bucket=s3_bucket_name,
            #     Key=file_key,
            #     Body=file,
            #     ContentType=file.content_type,
            # )

            s3_client.put_object(
                Bucket=s3_bucket_name,
                Key=file_key,
                Body=ciphertext,  # Encrypted content
                ContentType=file.content_type,
            )

            # Save metadata to MongoDB
            file_metadata = {
                "file_name": file_name,
                "file_type": file.content_type,
                "file_size": file_size,
                "file_key": str(file_key),
                "owner": owner_email,
                "sharing": [],
                "upload_date": datetime.datetime.utcnow(),
                "aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),  # Save encrypted AES key
                "nonce": base64.b64encode(cipher_aes.nonce).decode('utf-8'),    # Save nonce for AES
                "tag": base64.b64encode(tag).decode('utf-8')                    # Save authentication tag
            }
            files_collection.insert_one(file_metadata)

            # Prepare response
            uploaded_files.append({
                "file_name": file_metadata["file_name"],
                "file_type": file_metadata["file_type"],
                "file_size": file_metadata["file_size"],
                "file_key": file_metadata["file_key"],
                "owner": file_metadata["owner"],
                "upload_date": file_metadata["upload_date"].isoformat(),
                "_id": str(file_metadata["_id"])
            })

        return jsonify({"message": "Files uploaded successfully!", "files": uploaded_files}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/files/my_files", methods=["GET"])
@jwt_required()
def get_my_files():
    try:
        # Get the JWT identity (user email)
        owner_email = get_jwt_identity()

        # Fetch files where the current user is the owner
        my_files = files_collection.find({"owner": owner_email})

        # Convert the file data to a list of dictionaries with necessary fields
        file_list = []
        for file in my_files:
            file_list.append({
                "file_name": file["file_name"],
                "file_type": file["file_type"],
                "file_size": file["file_size"],
                "file_key": file["file_key"],
                "owner": file["owner"],
                "sharing": file["sharing"],
                #"upload_date": file["upload_date"].isoformat(),
                "_id": str(file["_id"])  # Convert ObjectId to string
            })

        return jsonify({"files": file_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/shared", methods=["GET"])
@jwt_required()
def get_shared_files():
    try:
        # Get the JWT identity (user email)
        current_user_email = get_jwt_identity()

        # Find files where the current user is in the sharing list
        shared_files = files_collection.find({"sharing": current_user_email})

        # Convert the file data to a list of dictionaries with necessary fields
        file_list = []
        for file in shared_files:
            file_list.append({
                "file_name": file["file_name"],
                "file_type": file["file_type"],
                "file_size": file["file_size"],
                "file_key": file["file_key"],
                "owner": file["owner"],
                #"upload_date": file["upload_date"].isoformat(),
                "_id": str(file["_id"])  # Convert ObjectId to string
            })

        return jsonify({"files": file_list}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/share-file", methods=["POST"])
@jwt_required()
def share_file():
    try:
        # Get the JWT identity (user email)
        owner_email = get_jwt_identity()
        # Get data from the request
        data = request.get_json()
        file_id = data.get("file_id")  # ID of the file to be shared
        share_email = data.get("email")  # Email of the person to share with
        if not file_id or not share_email:
            return jsonify({"error": "File ID and email are required"}), 400

        # Fetch the file by its ID
        file = files_collection.find_one({"_id": ObjectId(file_id), "owner": owner_email})
        if not file:
            return jsonify({"error": "File not found or you are not the owner"}), 404

        # Check if the user is already in the sharing list
        if share_email in file["sharing"]:
            return jsonify({"message": "File is already shared with this user"}), 200

        # Add the email to the sharing list
        files_collection.update_one(
            {"_id": ObjectId(file_id), "owner": owner_email},
            {"$push": {"sharing": share_email}}
        )

        # Return success message
        return jsonify({"message": "File shared successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/delete/<file_id>", methods=["DELETE"])
@jwt_required()
def delete_file(file_id):
    try:
        # Get the JWT identity (user email)
        owner_email = get_jwt_identity()
        print(owner_email)
        # Fetch the file from the database
        file = files_collection.find_one({"_id": ObjectId(file_id), "owner": owner_email})
        print(file)
        if not file:
            return jsonify({"error": "File not found or you are not the owner"}), 404

        # Get the S3 file key
        file_key = file["file_key"]

        # Delete the file from S3
        s3_client.delete_object(Bucket=s3_bucket_name, Key=file_key)

        # Remove the file entry from the database
        files_collection.delete_one({"_id": ObjectId(file_id)})

        return jsonify({"message": "File deleted successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/share/add", methods=["POST"])
@jwt_required()
def add_to_sharing_list():
    try:
        # Get the JWT identity (user email)
        owner_email = get_jwt_identity()

        # Get data from the request
        data = request.get_json()
        file_id = data.get("file_id")
        email = data.get("email")

        if not file_id or not email:
            return jsonify({"error": "File ID and email are required"}), 400

        # Check if the file exists and the user is the owner
        file = files_collection.find_one({"_id": ObjectId(file_id), "owner": owner_email})
        if not file:
            return jsonify({"error": "File not found or you are not the owner"}), 404

        # Add the email to the sharing list if not already added
        if email not in file.get("sharing", []):
            files_collection.update_one(
                {"_id": ObjectId(file_id)},
                {"$push": {"sharing": email}}
            )
            return jsonify({"message": "User added to the sharing list!"}), 200
        else:
            return jsonify({"message": "User already has access"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/files/revoke-access", methods=["POST"])
@jwt_required()
def revoke_access():
    try:
        # Get the JWT identity (user email)
        owner_email = get_jwt_identity()

        # Get data from the request
        data = request.get_json()
        file_id = data.get("file_id")
        email = data.get("email")
        print("Email",email,"file_id",file_id)
        if not file_id or not email:
            return jsonify({"error": "File ID and email are required"}), 400

        # Check if the file exists and the user is the owner
        file = files_collection.find_one({"_id": ObjectId(file_id), "owner": owner_email})
        if not file:
            return jsonify({"error": "File not found or you are not the owner"}), 404

        files_collection.update_one(
                {"_id": ObjectId(file_id)},
                {"$set": {"sharing": email}}  # Set the new sharing list
            )


        return jsonify({"message": "Access revoked successfully!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def fetch_encrypted_content(presigned_url):
    """
    Fetch encrypted content using the pre-signed URL.
    """
    try:
        # Make a GET request to fetch the file
        response = requests.get(presigned_url)
        if response.status_code == 200:
            encrypted_content = response.content
            print("Fetched Encrypted Content Successfully!")
            return encrypted_content
        else:
            print(f"Failed to fetch file. HTTP Status: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error fetching encrypted content: {str(e)}")
        return None

def get_presigned_url(bucket_name, key, expiration=3600):
    """
    Generate a pre-signed URL to fetch the file from S3.
    """
    try:
        # Generate a pre-signed URL
        presigned_url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': s3_bucket_name,
                'Key': key
            },
            ExpiresIn= 3600  # URL expiry time in seconds (default: 1 hour)
        )
        return presigned_url

    except NoCredentialsError:
        print("Credentials not available.")
        return None
    except PartialCredentialsError:
        print("Incomplete credentials provided.")
        return None
    except Exception as e:
        print(f"Error generating pre-signed URL: {str(e)}")
        return None



@app.route("/api/files/download/<file_key>", methods=["GET"])
@jwt_required()
def download_file(file_key):
    try:
        # Get the logged-in user's email
        user_email = get_jwt_identity()

        # Retrieve metadata from MongoDB
        file_metadata = files_collection.find_one({"file_key": file_key})
        if not file_metadata:
            return jsonify({"error": "File not found!"}), 404
        
        # Authorization check
        if file_metadata["owner"] != user_email and user_email not in file_metadata["sharing"]:
            return jsonify({"error": "You don't have access to this file!"}), 403

        # Fetch the encrypted file from S3
        presigned_url = get_presigned_url(s3_bucket_name, file_key)
        encrypted_content = b''
        if presigned_url:
            print("Pre-Signed URL:", presigned_url)

            # Fetch Encrypted Content as bytes
            encrypted_content = fetch_encrypted_content(presigned_url)

        print("S3 Fetched", file_metadata)

        # Retrieve AES key, nonce, and tag
        # encrypted_aes_key = file_metadata["aes_key"]
        # nonce = file_metadata["nonce"]
        # tag = file_metadata["tag"]

        encrypted_aes_key = base64.b64decode(file_metadata['aes_key'])
        nonce = base64.b64decode(file_metadata['nonce'])
        tag = base64.b64decode(file_metadata['tag'])

        # Decrypt the file
        decrypted_content = decrypt_file(
            encrypted_content,
            nonce,
            encrypted_aes_key,
            tag
        )

        #decrypted_content = decrypt_file(encrypted_content, nonce, encrypted_aes_key)
        # Return the decrypted content
        return jsonify({
            "file_name": file_metadata["file_name"],
            "content": base64.b64encode(decrypted_content).decode('utf-8'),
            "file_type": file_metadata["file_type"]
        }), 200
    except Exception as e:
        print("Error ",str(e))
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    app.run(debug=True)
