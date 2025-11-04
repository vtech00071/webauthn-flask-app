from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import webauthn
import webauthn.helpers.structs as webauthn_structs
import os
import base64
import json # We need this to handle the face descriptor list
from webauthn.helpers import (
    options_to_json, 
    parse_registration_credential_json, 
    parse_authentication_credential_json
)

app = Flask(__name__)
# A secret key is required for sessions (to track login status)
app.config['SECRET_KEY'] = 'your_webauthn_secret_key_12345'

# --- WebAuthn Server Configuration ---
RP_ID = 'webauthn-flask-app.onrender.com'
RP_NAME = 'My Fingerprint App'
EXPECTED_ORIGIN = 'https://webauthn-flask-app.onrender.com'

# --- In-Memory Database ---
# We've added 'face_descriptor': None to our user model
db = {
    "users": {},  # Stores user info by username
    "credentials": {}  # Stores credentials by user_id
}

# === Routes for Standard Pages ===

@app.route('/')
@app.route('/register')
def register():
    """Renders the registration page."""
    return render_template('register.html')


@app.route('/login')
def login():
    """Renders the login page."""
    return render_template('login.html')


@app.route('/success')
def success():
    """Renders the success page after a successful login."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    return render_template('success.html')

# === 1. FINGERPRINT (WebAuthn) REGISTRATION ===

@app.route('/register-begin', methods=['POST'])
def register_begin():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if username in db['users']:
        return jsonify({"error": "User already exists"}), 400

    user_id = os.urandom(32)
    # Add the new 'face_descriptor' field
    db['users'][username] = {
        "id": user_id,
        "username": username,
        "face_descriptor": None # New field for face AI
    }
    
    session['registration_user_id'] = base64.b64encode(user_id).decode('utf-8')
    session['registration_username'] = username

    options = webauthn.generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id,
        user_name=username,
    )

    session['challenge'] = options.challenge
    
    return app.response_class(
        response=options_to_json(options),
        mimetype="application/json"
    )


@app.route('/register-complete', methods=['POST'])
def register_complete():
    data = request.json
    challenge = session.get('challenge')
    user_id_b64 = session.get('registration_user_id')

    if not challenge or not user_id_b64:
        return jsonify({"error": "Session expired or invalid. Please try registering again."}), 400

    user_id = base64.b64decode(user_id_b64)

    try:
        credential = parse_registration_credential_json(data)
        
        registration_verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
        )
    except Exception as e:
        return jsonify({"error": f"Registration failed: {e}"}), 400

    if user_id not in db['credentials']:
        db['credentials'][user_id] = []
        
    db['credentials'][user_id].append(registration_verification)
    
    session.pop('registration_user_id', None)
    session.pop('registration_username', None)
    session.pop('challenge', None)
    
    return jsonify({"success": True, "message": "Registration successful!"})


# === 2. FINGERPRINT (WebAuthn) LOGIN ===

@app.route('/login-begin', methods=['POST'])
def login_begin():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = db['users'].get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id = user['id']
    saved_credentials = db['credentials'].get(user_id, [])
    if not saved_credentials:
        return jsonify({"error": "No credentials found for this user. Please register first."}), 404

    descriptors = []
    for cred in saved_credentials:
        descriptors.append(
            webauthn_structs.PublicKeyCredentialDescriptor(
                id=cred.credential_id,
                type=webauthn_structs.PublicKeyCredentialType.PUBLIC_KEY
            )
        )

    options = webauthn.generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=descriptors,
    )

    session['challenge'] = options.challenge
    session['login_user_id'] = base64.b64encode(user_id).decode('utf-8')
    
    return app.response_class(
        response=options_to_json(options),
        mimetype="application/json"
    )


@app.route('/login-complete', methods=['POST'])
def login_complete():
    data = request.json
    challenge = session.get('challenge')
    user_id_b64 = session.get('login_user_id')

    if not challenge or not user_id_b64:
        return jsonify({"error": "Session expired. Please try logging in again."}), 400

    user_id = base64.b64decode(user_id_b64)
    user_credentials = db['credentials'].get(user_id, [])

    try:
        raw_id_from_login = data.get('rawId')
        if not raw_id_from_login:
            return jsonify({"error": "Login data was missing rawId"}), 400
            
        matching_cred = None
        for cred in user_credentials:
            saved_id_b64 = base64.urlsafe_b64encode(cred.credential_id).decode('utf-8').rstrip('=')
            
            if saved_id_b64 == raw_id_from_login:
                matching_cred = cred
                break
        
        if not matching_cred:
            return jsonify({"error": "Credential not recognized."}), 400

        credential = parse_authentication_credential_json(data)

        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=matching_cred.credential_public_key,
            credential_current_sign_count=matching_cred.sign_count,
        )
        
        matching_cred.sign_count = verification.new_sign_count

    except Exception as e:
        return jsonify({"error": f"Login failed: {e}"}), 400

    session.pop('login_user_id', None)
    session.pop('challenge', None)
    session['logged_in'] = True

    return jsonify({"success": True, "message": "Login successful!"})


# === 3. FACE AI REGISTRATION & LOGIN (NEW) ===

@app.route('/register-face')
def register_face():
    """Serves the new 'register_face.html' page."""
    return render_template('register_face.html')


@app.route('/login-face')
def login_face():
    """Serves the new 'login_face.html' page."""
    return render_template('login_face.html')


@app.route('/save-face-descriptor', methods=['POST'])
def save_face_descriptor():
    """
    Saves the user's AI face signature (descriptor) to the database.
    NOTE: This assumes the user *already* has an account from fingerprint registration.
    """
    data = request.json
    username = data.get('username')
    descriptor = data.get('descriptor') # This will be a list of 128 numbers

    if not username or not descriptor:
        return jsonify({"error": "Username and descriptor are required"}), 400

    user = db['users'].get(username)
    if not user:
        return jsonify({"error": "User not found. Please register with fingerprint first."}), 404

    # Save the descriptor (as a JSON string)
    try:
        db['users'][username]['face_descriptor'] = json.dumps(descriptor)
        return jsonify({"success": True, "message": "Face registered successfully!"})
    except Exception as e:
        return jsonify({"error": f"Could not save face data: {e}"}), 500


@app.route('/get-face-descriptor', methods=['POST'])
def get_face_descriptor():
    """
    Retrieves a user's saved face descriptor for comparison.
    """
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    user = db['users'].get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    face_descriptor_str = user.get('face_descriptor')
    if not face_descriptor_str:
        return jsonify({"error": "No face descriptor registered for this user."}), 404

    # Send the saved descriptor (still a JSON string) back to the browser
    return jsonify({
        "success": True,
        "descriptor": json.loads(face_descriptor_str) # Convert back to a list
    })

# === Run the Application ===




@app.route('/login-complete-face-dummy')
def login_complete_face_dummy():
    """
    A simple dummy route for the face AI to call.
    This sets the session to 'logged_in' = True.
    """
    session['logged_in'] = True
    return jsonify({"success": True})


if __name__ == '__main__':
    app.run(debug=True, port=8090)