from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import webauthn
import webauthn.helpers.structs as webauthn_structs
import os
import base64
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

# === 1. REGISTRATION LOGIC ===

@app.route('/register-begin', methods=['POST'])
def register_begin():
    data = request.json
    username = data.get('username')

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if username in db['users']:
        return jsonify({"error": "User already exists"}), 400

    user_id = os.urandom(32)
    db['users'][username] = {
        "id": user_id,
        "username": username
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
    """
    Completes the registration process.
    Verifies the challenge response from the browser/phone.
    """
    data = request.json
    challenge = session.get('challenge')
    user_id_b64 = session.get('registration_user_id')

    if not challenge or not user_id_b64:
        return jsonify({"error": "Session expired or invalid. Please try registering again."}), 400

    user_id = base64.b64decode(user_id_b64)

    try:
        credential = parse_registration_credential_json(data)
        
        registration_verification = webauthn.verify_registration_response(
            credential=credential, # Pass the parsed object
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
        )
    except Exception as e:
        return jsonify({"error": f"Registration failed: {e}"}), 400

    # Save the new, verified credential to our "database"
    if user_id not in db['credentials']:
        db['credentials'][user_id] = []
        
    db['credentials'][user_id].append(registration_verification)
    
    # Clear session and return success
    session.pop('registration_user_id', None)
    session.pop('registration_username', None)
    session.pop('challenge', None)
    
    return jsonify({"success": True, "message": "Registration successful!"})


# === 2. LOGIN LOGIC ===

@app.route('/login-begin', methods=['POST'])
def login_begin():
    """
    Starts the login process.
    Finds the's credentials and sends a new challenge.
    """
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

    # Transform our saved credentials into the format the library needs
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
        allow_credentials=descriptors, # Pass the new, correctly-formatted list
    )

    session['challenge'] = options.challenge
    session['login_user_id'] = base64.b64encode(user_id).decode('utf-8')
    
    return app.response_class(
        response=options_to_json(options),
        mimetype="application/json"
    )


@app.route('/login-complete', methods=['POST'])
def login_complete():
    """
    Completes the login process.
    Verifies the login challenge response.
    """
    data = request.json # This is the assertionForServer from main.js
    challenge = session.get('challenge')
    user_id_b64 = session.get('login_user_id')

    if not challenge or not user_id_b64:
        return jsonify({"error": "Session expired. Please try logging in again."}), 400

    user_id = base64.b64decode(user_id_b64)
    user_credentials = db['credentials'].get(user_id, [])

    try:
        # --- THIS IS THE FIX ---
        # Get the rawId (as a Base64-URL string) from the login data
        raw_id_from_login = data.get('rawId')
        if not raw_id_from_login:
            return jsonify({"error": "Login data was missing rawId"}), 400
            
        # Find the matching credential from our database
        matching_cred = None
        for cred in user_credentials:
            # Convert the *saved* credential ID (bytes) into a Base64-URL string
            saved_id_b64 = base64.b64encode(cred.credential_id).decode('utf-8') \
                .replace('+', '-').replace('/', '_').rstrip('=')
            
            # Now we compare string to string. This is 100% reliable.
            if saved_id_b64 == raw_id_from_login:
                matching_cred = cred
                break
        
        if not matching_cred:
            # This is the error you are seeing.
            return jsonify({"error": "Credential not recognized."}), 400
        # --- END FIX ---

        # Now that we have the matching_cred, we can proceed
        credential = parse_authentication_credential_json(data)

        # Verify the login
        verification = webauthn.verify_authentication_response(
            credential=credential, # Pass the parsed object
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=matching_cred.public_key,
            credential_current_sign_count=matching_cred.sign_count,
        )
        
        # Update the signature count to prevent replay attacks
        matching_cred.sign_count = verification.new_sign_count

    except Exception as e:
        return jsonify({"error": f"Login failed: {e}"}), 400

    # Clear session and mark user as "logged in"
    session.pop('login_user_id', None)
    session.pop('challenge', None)
    session['logged_in'] = True

    return jsonify({"success": True, "message": "Login successful!"})


# === Run the Application ===

if __name__ == '__main__':
    app.run(debug=True, port=8090)