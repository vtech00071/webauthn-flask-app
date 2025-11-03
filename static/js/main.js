/* === WebAuthn Helper Functions === */

// Converts ArrayBuffer to Base64 (URL-safe)
function bufferToBase64(buffer) {
    const byteArray = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < byteArray.length; i++) {
        str += String.fromCharCode(byteArray[i]);
    }
    // btoa is for binary to ASCII (Base64)
    // The replace calls make it URL-safe
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Converts Base64 (URL-safe) to ArrayBuffer
function base64ToBuffer(base64) {
    // Add back any padding
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    
    // atob is for ASCII to binary
    const str = atob(base64);
    const buffer = new ArrayBuffer(str.length);
    const byteArray = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
        byteArray[i] = str.charCodeAt(i);
    }
    return buffer;
}

// Helper to show messages to the user
function showMessage(message, isError = false) {
    const messageArea = document.getElementById('message-area');
    if (messageArea) {
        // Clear previous messages
        messageArea.innerHTML = ''; 
        
        // Create new message element
        const messageEl = document.createElement('p');
        messageEl.textContent = message;
        messageEl.className = isError ? 'message error' : 'message success';
        
        messageArea.appendChild(messageEl);
    }
}

// A helper to handle fetch responses
async function handleFetchResponse(response) {
    if (!response.ok) {
        // If server crashed (500) or sent bad data,
        // it might not send JSON.
        const text = await response.text();
        let error = text;
        try {
            // Try to parse as JSON, maybe it's a {error: "..."}
            const data = JSON.parse(text);
            error = data.error || text;
        } catch (e) {
            // It's not JSON, just show the HTML crash report
            error = text;
        }
        // This stops the function
        throw new Error(error);
    }
    // If response is OK, it must be JSON
    return response.json();
}


/* === 1. REGISTRATION LOGIC === */

const registerButton = document.getElementById('register-button');

if (registerButton) {
    registerButton.addEventListener('click', async () => {
        const usernameInput = document.getElementById('username');
        const username = usernameInput.value;
        
        if (!username) {
            showMessage('Please enter a username', true);
            return;
        }

        try {
            // 1. Get the challenge from our server
            const response = await fetch('/register-begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username }),
            });
            
            const options = await handleFetchResponse(response);
            
            // 2. Convert server's Base64 to ArrayBuffer for the browser
            options.challenge = base64ToBuffer(options.challenge);
            options.user.id = base64ToBuffer(options.user.id);

            // 3. Ask the browser to create a new credential (triggers fingerprint scan)
            const credential = await navigator.credentials.create({
                publicKey: options
            });

            // 4. Convert browser's ArrayBuffer to Base64 for the server
            const credentialForServer = {
                id: credential.id,
                type: credential.type,
                rawId: bufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                    attestationObject: bufferToBase64(credential.response.attestationObject),
                },
            };

            // 5. Send the signed credential to our server to be verified and saved
            const completeResponse = await fetch('/register-complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(credentialForServer),
            });
            
            const completeData = await handleFetchResponse(completeResponse);

            showMessage(completeData.message, false);
            // On success, automatically send user to the login page
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);

        } catch (e) {
            // This 'catch' block will show all errors
            // from fetch, or registration, or user cancellation.
            showMessage(`Error: ${e.message}`, true);
        }
    });
}

/* === 2. LOGIN LOGIC === */

const loginButton = document.getElementById('login-button');

if (loginButton) {
    loginButton.addEventListener('click', async () => {
        const usernameInput = document.getElementById('username');
        const username = usernameInput.value;
        
        if (!username) {
            showMessage('Please enter a username', true);
            return;
        }

        try {
            // 1. Get the login challenge from our server
            const response = await fetch('/login-begin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username }),
            });
            
            const options = await handleFetchResponse(response);

            // 2. Convert all challenges and IDs from Base64 to ArrayBuffer
            options.challenge = base64ToBuffer(options.challenge);
            if (options.allowCredentials) {
                for (let cred of options.allowCredentials) {
                    cred.id = base64ToBuffer(cred.id);
                }
            }

            // 3. Ask the browser to get an assertion (triggers fingerprint scan)
            const assertion = await navigator.credentials.get({
                publicKey: options
            });

            // 4. Convert the assertion's ArrayBuffers to Base64 to send to server
            const assertionForServer = {
                id: assertion.id,
                type: assertion.type,
                rawId: bufferToBase64(assertion.rawId),
                response: {
                    clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
                    authenticatorData: bufferToBase64(assertion.response.authenticatorData),
                    signature: bufferToBase64(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64(assertion.response.userHandle) : null,
                },
            };

            // 5. Send the signed assertion to our server to be verified
            const completeResponse = await fetch('/login-complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(assertionForServer),
            });

            const completeData = await handleFetchResponse(completeResponse);

            showMessage(completeData.message, false);
            // On success, send user to the success page!
            setTimeout(() => {
                window.location.href = '/success';
            }, 1000);

        } catch (e) {
            // This 'catch' block will show all errors
            showMessage(`Error: ${e.message}`, true);
        }
    });
}