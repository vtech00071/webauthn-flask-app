/* === FACE-API.JS (AI) LOGIC === */

// Find all the elements we need from the HTML
const video = document.getElementById('video');
const messageArea = document.getElementById('message-area');
const registerButton = document.getElementById('register-face-button');
const loginButton = document.getElementById('login-face-button');

// --- 1. LOAD AI MODELS ---
// We need to load the AI models from the internet.
// This function runs automatically when the script loads.
Promise.all([
    faceapi.nets.tinyFaceDetector.loadFromUri('/static/models'),
    faceapi.nets.faceLandmark68Net.loadFromUri('/static/models'),
    faceapi.nets.faceRecognitionNet.loadFromUri('/static/models'),
    faceapi.nets.ssdMobilenetv1.loadFromUri('/static/models') // Added for better detection
]).then(startVideo);

// --- 2. START THE VIDEO CAMERA ---
async function startVideo() {
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: {} });
        video.srcObject = stream;
    } catch (err) {
        console.error("Camera Error:", err);
        showMessage("Could not access the camera. Please allow camera permissions.", true);
    }
}

// --- 3. HELPER to show messages ---
function showMessage(message, isError = false) {
    if (messageArea) {
        messageArea.innerHTML = ''; // Clear old messages
        const messageEl = document.createElement('p');
        messageEl.textContent = message;
        messageEl.className = isError ? 'message error' : 'message success';
        messageArea.appendChild(messageEl);
    }
}

// --- 4. HELPER to get face descriptor ---
// This is the core AI function.
// It finds a face in the video and computes the "face signature".
async function getFaceDescriptor() {
    showMessage("Scanning for face...", false);
    
    // Detect a single face
    const detection = await faceapi.detectSingleFace(video)
                                   .withFaceLandmarks()
                                   .withFaceDescriptor();
    
    if (!detection) {
        showMessage("No face detected. Please look at the camera.", true);
        return null;
    }
    
    showMessage("Face detected!", false);
    return detection.descriptor; // This is the list of 128 numbers
}


/* === 5. FACE REGISTRATION LOGIC === */

if (registerButton) {
    registerButton.addEventListener('click', async () => {
        const username = document.getElementById('username').value;
        if (!username) {
            showMessage("Please enter your username first.", true);
            return;
        }

        // 1. Get the face signature from the camera
        const descriptor = await getFaceDescriptor();
        if (!descriptor) {
            return; // Error message was already shown
        }
        
        // 2. Send the descriptor (list of numbers) to our server
        try {
            const response = await fetch('/save-face-descriptor', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: username, 
                    descriptor: Array.from(descriptor) // Convert to a simple array
                }),
            });
            
            const data = await response.json();

            if (response.ok) {
                showMessage(data.message, false);
                setTimeout(() => {
                    window.location.href = '/login'; // Go to login page on success
                }, 2000);
            } else {
                showMessage(data.error, true);
            }
        } catch (e) {
            showMessage(`Network error: ${e.message}`, true);
        }
    });
}




/* === 6. FACE LOGIN LOGIC === */

if (loginButton) {
    loginButton.addEventListener('click', async () => {
        const username = document.getElementById('username').value;
        if (!username) {
            showMessage("Please enter your username.", true);
            return;
        }

        try {
            // 1. Get the *SAVED* descriptor from our server
            const response = await fetch('/get-face-descriptor', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username }),
            });
            
            const data = await response.json();
            if (!response.ok) {
                showMessage(data.error, true);
                return;
            }
            
            // The saved descriptor (list of 128 numbers)
            const savedDescriptor = new Float32Array(data.descriptor);
            
            // 2. Get the *CURRENT* descriptor from the live camera
            const currentDescriptor = await getFaceDescriptor();
            if (!currentDescriptor) {
                return; // Error already shown
            }

            // 3. Compare the two descriptors
            const faceMatcher = new faceapi.FaceMatcher([savedDescriptor]);
            const bestMatch = faceMatcher.findBestMatch(currentDescriptor);

            if (bestMatch.label === 'person 1' && bestMatch.distance < 0.5) {
                // MATCH! (A distance < 0.5 is a very good match)
                showMessage("Login Successful! Redirecting...", false);
                
                // We need a simple fetch to tell the server we are logged in
                // (This is a simplified way to set the session)
                await fetch('/login-complete-face-dummy'); 
                
                setTimeout(() => {
                    window.location.href = '/success';
                }, 1000);
                
            } else {
                // NO MATCH
                showMessage("Face not recognized. Please try again.", true);
            }
            
        } catch (e) {
            showMessage(`Error: ${e.message}`, true);
        }
    });
}