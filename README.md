# Secure Ephemeral File Sharing System

A secure file-sharing application designed to share files temporarily, with browser-side encryption, optional password protection, one-time downloads, and automatic expiration.

## 1. Overview

The Secure Ephemeral File Sharing System allows users to upload a file, generate a shareable link, and let a recipient access the file under predefined security constraints.

The application encrypts file contents in the browser before uploading them to the backend. The server stores the encrypted file blob and the metadata required to manage access, expiration, and download verification.

The system is designed around three core principles:

- **Confidentiality:** File encryption and decryption take place on the client side.
- **Controlled access:** Download requests are verified using an encryption-key hash and, optionally, a password.
- **Ephemeral availability:** Shared files have a configurable time-to-live (TTL) and are intended for one-time access.

## 2. Features

- **Client-side encryption:** Uses the browser's Web Crypto API with AES-GCM to encrypt files before upload.
- **Client-side decryption:** The recipient decrypts the downloaded file in the browser.
- **Key separation:** The raw encryption key is not sent to the backend as part of the upload request.
- **Optional password protection:** Passwords are hashed using Argon2id before being stored by the backend.
- **Time-limited sharing:** Supports a configurable TTL from 1 second to 7 days.
- **One-time downloads:** Uses a conditional database update within a transaction to prevent multiple requests from claiming the same file.
- **Automatic cleanup:** A scheduled task removes expired file records and their corresponding stored blobs.
- **Download rate limiting:** Limits download attempts per IP address.
- **Metadata endpoint:** Provides information about a shared file without returning the encrypted blob or raw encryption key.

## 3. Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| Frontend | React, Vite | User interface |
| Browser cryptography | Web Crypto API | Client-side encryption and decryption |
| Encryption | AES-GCM | Confidentiality and authenticated encryption |
| Backend | Node.js, Express | Upload, download, and access-control APIs |
| Database | SQLite | File metadata and access state |
| Password hashing | Argon2id | Password hash generation and verification |
| Identifiers | UUID | Unique identifiers for shared files |
| Scheduled cleanup | `node-cron` | Periodic expiration cleanup |
| Network inspection | mitmproxy | Optional authorized traffic testing |

## 4. Architecture

```text
                  SENDER'S BROWSER
                         |
                  Select a file
                         |
                  Generate key
                         |
                  Encrypt using
                      AES-GCM
                         |
                  Calculate key hash
                         |
                   POST /upload
                         |
                         v
                   EXPRESS BACKEND
                     Port 3001
                         |
                  Validate request
                         |
                 Hash optional password
                    using Argon2id
                         |
              +----------+-----------+
              |                      |
              v                      v
       Encrypted file blob       SQLite database
       backend/uploads/          File metadata,
       <UUID>.bin                key hash, password
                                 hash, expiry, state
              |                      |
              +----------+-----------+
                         |
                     Share link
                         |
                         v
                 RECIPIENT'S BROWSER
                         |
                 Read file ID and key
                         |
                 Request file access
                         |
                  POST /download/:id
                         |
                 Verify access details
                         |
                 Claim one-time access
                         |
                 Return encrypted blob
                         |
                 Decrypt using AES-GCM
                         |
                   Download file