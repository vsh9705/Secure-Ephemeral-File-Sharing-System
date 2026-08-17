// crypto.js
// All cryptographic operations run here — in the browser — using the
// native Web Crypto API (window.crypto.subtle). No library, no server.
// This is the implementation of DP1, DP2, DP4, DP5, and DP6.

const subtle = window.crypto.subtle;

// ─── Key generation ────────────────────────────────────────────────────────
// DP1: Encryption key is generated exclusively on the client.
// AES-GCM 256-bit is the standard for authenticated symmetric encryption.
export async function generateKey() {
  return subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,   // extractable — we need to export it for the share URL
    ['encrypt', 'decrypt']
  );
}

// Export a CryptoKey to raw bytes
export async function exportKey(cryptoKey) {
  return subtle.exportKey('raw', cryptoKey);
}

// Import raw bytes back into a CryptoKey for decryption
export async function importKey(rawBytes) {
  return subtle.importKey(
    'raw',
    rawBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

// Encode a key to a base64url string (URL-safe, for the #fragment)
export function keyToBase64(rawKeyBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(rawKeyBuffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Decode a base64url string back to an ArrayBuffer
export function base64ToKey(b64) {
  const b64standard = b64.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ─── Encryption ────────────────────────────────────────────────────────────
// DP2: File is encrypted in the browser before being sent to the server.
// AES-GCM with a random 12-byte IV. The IV is prepended to the ciphertext
// so the server stores [IV || ciphertext] as a single blob.
export async function encryptFile(file, cryptoKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const fileBuffer = await file.arrayBuffer();

  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    fileBuffer
  );

  // Combine IV + ciphertext into one Uint8Array
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);

  return combined;
}

// ─── Decryption ────────────────────────────────────────────────────────────
// DP6: Decryption happens in the browser after downloading the ciphertext.
// The server only ever sends the blob — it cannot decrypt it.
export async function decryptBlob(encryptedBase64, cryptoKey) {
  const encryptedBytes = base64Decode(encryptedBase64);

  // Split IV (first 12 bytes) from ciphertext (rest)
  const iv = encryptedBytes.slice(0, 12);
  const ciphertext = encryptedBytes.slice(12);

  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );

  return plaintext;
}

// ─── Hash computation ──────────────────────────────────────────────────────
// DP5: The client computes SHA-256(key) and sends only the hash to the server.
// The server verifies the hash — it never sees the raw key.
export async function hashKey(rawKeyBuffer) {
  const hashBuffer = await subtle.digest('SHA-256', rawKeyBuffer);
  return bufferToHex(hashBuffer);
}

// ─── URL fragment encoding ─────────────────────────────────────────────────
// DP4: The decryption key is embedded in the URL fragment (#).
// The browser never sends the fragment to the server — it is client-only.
// Standard HTTP/HTTPS semantics guarantee this.
export function buildShareURL(fileId, rawKeyBuffer) {
  const keyB64 = keyToBase64(rawKeyBuffer);
  const base = window.location.origin;
  // Format: http://localhost:5173/download#id=<fileId>&key=<base64key>
  return `${base}/download#id=${fileId}&key=${keyB64}`;
}

export function parseShareURL() {
  const fragment = window.location.hash.slice(1); // remove leading #
  const params = new URLSearchParams(fragment);
  return {
    id: params.get('id'),
    key: params.get('key'),
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function base64Decode(b64) {
  const b64standard = b64.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function uint8ArrayToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}