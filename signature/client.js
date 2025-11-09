const io = require("socket.io-client");
const readline = require("readline");
// 1. Import 'crypto' for both hashing (from A1) and RSA keys.
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
const users = new Map(); // Stores other users' public keys (username -> publicKey)

// 2. Generate our own unique RSA key pair on startup.
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048, // Standard, strong key length
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// We store our keys in variables. The privateKey NEVER leaves this client.
const myPrivateKey = privateKey;
const myPublicKey = publicKey;


socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input; // Our real, registered username
    console.log(`Welcome, ${username} to the chat`);

    // 3. Send our REAL, generated public key to the server.
    socket.emit("registerPublicKey", {
      username,
      publicKey: myPublicKey, // No more dummy string
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          username = match[1]; // Change our *display* name
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername; // Change back to our real name
          console.log(`Now you are ${username}`);
        } else {
          // 4. This is a normal message. We must SIGN it.
          
          // 5. Sign the message text with our private key.
          const signature = crypto.sign("sha256", Buffer.from(message), myPrivateKey);
          
          // 6. Create the JSON payload
          const payload = {
            originalMessage: message,
            // Send the signature as a hex string
            signature: signature.toString('hex') 
          };

          // 7. Send the JSON string as the 'message'
          socket.emit("message", { 
            username, // This is our 'claimed' username (could be fake)
            message: JSON.stringify(payload) // This contains our 'proof'
          });
        }
      }
      rl.prompt();
    });
  });
});

// Receives the list of users already in the chat
socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

// Receives new users who join after us
socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  // Don't log if it's just us joining
  if (username !== registeredUsername) {
    users.set(username, publicKey);
    console.log(`\n${username} joined the chat`);
    rl.prompt();
  }
});

// This is the core logic for Assignment 2
socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage } = data;

  // UI fix: clear the current line
  readline.clearLine(process.stdout, 0);
  readline.cursorTo(process.stdout, 0);

  // We don't need to verify our own messages, just show the prompt
  if (senderUsername === registeredUsername) {
      rl.prompt(true);
      return; 
  }

  // 8. Try to parse the JSON payload from the sender
  try {
    const payload = JSON.parse(senderMessage);
    const { originalMessage, signature: senderSignature } = payload;

    // 9. Look up the sender's *claimed* public key
    const senderPublicKey = users.get(senderUsername);

    if (!senderPublicKey) {
      // We don't have a public key for this user.
      console.log(`[Received message from unknown user ${senderUsername}]`);
      rl.prompt(true);
      return;
    }

    // 10. Verify the signature!
    // This checks: "Was this 'originalMessage' signed by the
    // private key that matches this 'senderPublicKey'?"
    const isVerified = crypto.verify(
      "sha256", // The algorithm must match crypto.sign
      Buffer.from(originalMessage), // The data that was signed
      senderPublicKey, // The public key of the *claimed* user
      Buffer.from(senderSignature, 'hex') // The signature itself
    );

    // 11. Check the verification result
    if (isVerified) {
      // --- SIGNATURE IS VALID ---
      // This is a real message from the real user.
      console.log(`${senderUsername}: ${originalMessage}`);
    } else {
      // --- SIGNATURE IS FAKE ---
      // This is an impersonation!
      // The 'senderUsername' does not match the 'senderSignature'
      console.log(`[WARNING: this user is fake! User '${senderUsername}' is an IMPERSONATOR!]`);
      console.log(`> ${originalMessage}`);
    }

  } catch (error) {
    // This happens if the message wasn't JSON.
    // (e.g., from an old client, or a tampered hash from A1)
    console.log(`[Received a non-standard message from ${senderUsername}]`);
    console.log(`> ${senderMessage}`);
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