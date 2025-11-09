const io = require("socket.io-client");
const readline = require("readline");
// 1. Import 'crypto' for hashing.
const crypto = require("crypto"); 

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let username = "";

// Helper function creates a SHA-256 hash.
// This "fingerprint" checks for tampering.
function getHash(message) {
  return crypto.createHash('sha256').update(message).digest('hex');
}

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    console.log(`Welcome, ${username} to the chat`);
    rl.prompt();

    // Runs when user presses 'Enter'
    rl.on("line", (message) => {
      if (message.trim()) {
        // 2. Create a hash of the original message.
        const hash = getHash(message);
        
        // 3. Create a JSON payload with the message AND its hash.
        const payload = {
          originalMessage: message,
          hash: hash
        };

        // 4. This is the trick: We send a JSON string *inside* the
        //    'message' field, since the server only passes 'message'.
        socket.emit("message", { 
          username, 
          message: JSON.stringify(payload) 
        });
      }
      // No rl.prompt() here, 'on("message")' will handle it.
    });
  });
});

// Runs when we receive a message from the server.
socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage } = data;

  // UI fix: clear the current line before printing.
  readline.clearLine(process.stdout, 0);
  readline.cursorTo(process.stdout, 0);

  // 5. We use a try...catch to detect tampering.
  try {
    // We try to parse the JSON string.
    // This FAILS if the malicious server added "(sus?)".
    const payload = JSON.parse(senderMessage);
    const { originalMessage, hash: senderHash } = payload;

    // Check if payload format is correct.
    if (!originalMessage || !senderHash) {
      throw new Error("Invalid payload structure");
    }

    // 6. If parsing worked, we calculate our own hash.
    const recipientHash = getHash(originalMessage);

    // 7. Verify the integrity.
    if (recipientHash === senderHash) {
      // --- HASHES MATCH ---
      // Message is safe (from normal server.js).

      // Don't show our own messages (prevents duplicates).
      if (senderUsername !== username) {
        console.log(`${senderUsername}: ${originalMessage}`);
      }

    } else {
      // --- HASHES DO NOT MATCH ---
      // This is a rare case (e.g., manual tampering).
      handleTampering(senderUsername, "Hash mismatch");
    }

  } catch (error) {
    // 8. --- JSON PARSING FAILED ---
    // This WILL happen with malicious-server.js.
    // We caught the tampering!
    handleTampering(senderUsername, `Invalid message format (tampered by server)`);
  }

  rl.prompt(true); // Show the ">" prompt again
});

// Helper function to show warnings.
function handleTampering(senderUsername, reason) {
  // Check if we were the sender or receiver.
  if (senderUsername === username) {
    // Warn the sender their message was changed.
    console.log(`[SERVER WARNING: Your message was TAMPERED with!]`);
    console.log(`> Reason: ${reason}`);
    console.log(`> The message was NOT delivered correctly.`);
  } else {
    // Warn the receiver the message is fake.
    console.log(`[WARNING: TAMPERED MESSAGE from ${senderUsername}]`);
    console.log(`> Reason: ${reason}`);
  }
}

// Cleanup code for server disconnect...
socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

// ...and for Ctrl+C.
socket.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});