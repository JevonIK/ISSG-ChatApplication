const io = require("socket.io-client");
const readline = require("readline");
// 1. Import 'crypto' to generate RSA keys and encrypt
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = ""; // The user we are secretly chatting with
let username = ""; // Our own username
const users = new Map(); // Stores everyone's publicKey (username -> publicKey)

// 2. GENERATE OUR RSA KEYS (Taken from Assignment 2)
// This is the important part missing from the tutorial's TLDR
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Store our keys. The privateKey is NEVER sent.
const myPrivateKey = privateKey;
const myPublicKey = publicKey;

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);

    // 3. Register our REAL PUBLIC KEY with the server
    socket.emit("registerPublicKey", {
      username,
      publicKey: myPublicKey, // <-- Sending the real key, NOT the string "public key"
    });
    rl.prompt();

    // 4. NEW MESSAGE SENDING LOGIC
    rl.on("line", (message) => {
      if (message.trim()) {
        if ((match = message.match(/^!secret (\w+)$/))) {
          // Command to start a secret chat
          targetUsername = match[1];
          console.log(`Now secretly chatting with ${targetUsername}`);
          
        } else if (message.match(/^!exit$/)) {
          // Command to stop the secret chat
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";

        } else if (targetUsername) {
          // --- SENDING A SECRET MESSAGE ---
          const targetPublicKey = users.get(targetUsername);
          if (!targetPublicKey) {
            console.log(`[Error: Unknown user or user has no public key: ${targetUsername}]`);
          } else {
            // Encrypt the message using the target's Public Key
            const ciphertext = crypto.publicEncrypt(
              targetPublicKey,
              Buffer.from(message)
            );

            // Create a JSON payload for the secret message
            const payload = {
              type: "private",
              target: targetUsername,
              ciphertext: ciphertext.toString('hex')
            };

            // Send the JSON string
            socket.emit("message", { 
              username, 
              message: JSON.stringify(payload) 
            });
          }
        } else {
          // --- SENDING A PUBLIC MESSAGE ---
          // Create a JSON payload for the public message
          const payload = {
            type: "public",
            originalMessage: message
          };
          // Send the JSON string
          socket.emit("message", { 
            username, 
            message: JSON.stringify(payload) 
          });
        }
      }
      rl.prompt();
    });
  });
});

// Receive the list of users when we join
socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

// Receive new users who join after us
socket.on("newUser", (data) => {
  const { username: newUsername, publicKey } = data; // Renamed to avoid conflict
  if (newUsername !== username) { // Use our own username for comparison
    users.set(newUsername, publicKey);
    console.log(`\n${newUsername} joined the chat`);
    rl.prompt();
  }
});

// 5. NEW MESSAGE RECEIVING LOGIC
socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage } = data;

  // UI Fix: clear the prompt line
  readline.clearLine(process.stdout, 0);
  readline.cursorTo(process.stdout, 0);

  // Don't show our own messages (prevents duplicates)
  if (senderUsername === username) {
      rl.prompt(true);
      return; 
  }

  // Try to parse the message as JSON
  try {
    const payload = JSON.parse(senderMessage);

    if (payload.type === "private") {
      // --- THIS IS A SECRET MESSAGE ---

      // Check if this message is for us
      if (payload.target === username) {
        // IT'S FOR US (We are Bob)
        const ciphertext = Buffer.from(payload.ciphertext, 'hex');
        // Decrypt using our OWN PRIVATE KEY
        const plaintext = crypto.privateDecrypt(
          myPrivateKey,
          ciphertext
        ).toString('utf8');
        
        console.log(`${senderUsername} (secret): ${plaintext}`);

      } else {
        // IT'S NOT FOR US (We are Trudy)
        // Show the actual gibberish ciphertext
        console.log(`${senderUsername}: ${payload.ciphertext}`);
      }

    } else if (payload.type === "public") {
      // --- THIS IS A PUBLIC MESSAGE ---
      // Show it as normal
      console.log(`${senderUsername}: ${payload.originalMessage}`);
    }

  } catch (error) {
    // This message was not JSON (maybe from an old client or error)
    // Show it as-is
    console.log(`${senderUsername}: ${senderMessage}`);
  }
  
  rl.prompt(true);
});


socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

socket.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});