# Local security evaluation lab guide

This is a terminal-by-terminal guide for running the eight controlled attacks
against your own local application. Do not run them while a real file is
waiting to be downloaded: the test scripts use the same database and uploads
folder as the application.

Every script creates a small AES-GCM encrypted test file, attacks it through
the real local API, and prints PASS or FAIL. They target only
http://localhost:3001.

## Before you start

You need the repository at /home/vasu/repos/btp and the Conda environment
named security. It contains Python, requests, cryptography, and mitmproxy.
You need three terminal windows. A fourth is needed only for the optional
browser proxy demonstration.

Do not run two backend servers. If one is already running, go to its terminal
and press Ctrl+C before starting this lab.

## Terminal 1: start the backend

Open a new terminal. Run the following commands, one at a time:

~~~bash
source /home/vasu/miniconda3/bin/activate security
conda env list
~~~

Your prompt should start with (security). The output of conda env list should
show an asterisk on the security line.

Now run:

~~~bash
cd /home/vasu/repos/btp/backend
node server.js > server.log 2>&1
~~~

Leave this command running. It may look blank because its messages are being
written to backend/server.log. This is intentional: A7 reads that log.

To inspect the backend log without stopping the server, use another terminal:

~~~bash
tail -n 30 /home/vasu/repos/btp/backend/server.log
~~~

## Terminal 2: prepare the attack runner

Open a second terminal and run:

~~~bash
source /home/vasu/miniconda3/bin/activate security
cd /home/vasu/repos/btp
python -c "import requests, cryptography; print('Python libraries are ready')"
curl http://localhost:3001/health
~~~

Expected output:

~~~text
Python libraries are ready
{"status":"ok"}
~~~

If curl cannot connect, return to Terminal 1. Ensure node server.js is still
running and check the last 30 lines of backend/server.log.

## Optional Terminal 3: start the normal browser application

The automated tests A1 through A7 do not require the frontend. To use the UI
as well, open a third terminal and run:

~~~bash
cd /home/vasu/repos/btp/frontend
npm run dev
~~~

Open the Local address printed by Vite, normally http://localhost:5173.

## Critical rate-limit rule

The backend allows ten download attempts from one IP address in one minute.
A4 and A5 deliberately use that limit. After A4, wait 65 seconds before A5.
After A5, wait another 65 seconds before A6:

~~~bash
sleep 65
~~~

This command prints nothing. Do not try to clear the limit by restarting the
backend: attempts are stored in SQLite, so a restart does not clear them.

## Attack order

Run every command in Terminal 2 from /home/vasu/repos/btp. Wait for a verdict
before running the next command.

| Attack | Command |
| --- | --- |
| A1 | python attacks/a1_db_dump.py |
| A2 | python attacks/a2_blob_exfil.py |
| A3 | python attacks/a3_replay.py |
| A4 | python attacks/a4_bruteforce_key.py |
| wait | sleep 65 |
| A5 | python attacks/a5_bruteforce_password.py |
| wait | sleep 65 |
| A6 | python attacks/a6_ttl_bypass.py |
| A7 | python attacks/a7_log_inspection.py |

The detailed interpretation for each attack follows.

## A1 — Database-dump attack

### Attacker story

The attacker copied backend/fileshare.db from server storage and wants to find
the AES key, plaintext, or a usable password.

### Command

~~~bash
python attacks/a1_db_dump.py
~~~

### What the script does

It uploads a real encrypted fixture with a password, then opens the SQLite
database directly and checks its schema and inserted row.

### Passing result

The UUID changes each run. These lines must be true:

~~~text
Schema has no raw-key column: True
Password is stored as Argon2id: True
Known plaintext marker absent from DB: True
VERDICT: PASS
~~~

### Presentation wording

“A database compromise reveals metadata, a key verifier, and an Argon2id
password hash. It does not reveal the raw AES key or the test file plaintext,
so the database dump alone cannot decrypt the file.”

Do not claim metadata is hidden. Filenames, MIME types, timestamps, and blob
paths are stored in the database.

## A2 — Encrypted-blob theft attack

### Attacker story

The attacker stole a .bin file from backend/uploads but did not obtain the
browser's AES key.

### Command

~~~bash
python attacks/a2_blob_exfil.py
~~~

### Passing result

~~~text
Known plaintext bytes absent from stolen blob: True
AES-GCM rejects decryption with an attacker key: True
VERDICT: PASS
~~~

### Presentation wording

“Storage theft yields ciphertext. AES-GCM rejects decryption with any key
other than the original client-generated 256-bit key.”

If the script says the blob is missing, run it again immediately. The fixture
has a short expiry time.

## A3 — One-time-link replay race

### Attacker story

Two recipients have the same valid link and submit download requests at the
same time. The attacker wants both requests to receive the ciphertext.

### Command

~~~bash
python attacks/a3_replay.py
~~~

### Passing result

~~~text
Concurrent request status codes: [200, 404]
VERDICT: PASS
~~~

The order can be [404, 200]. Exactly one 200 is the requirement. The rejected
request is usually 404 because the successful request deletes the record. A
410 rejection is also safe.

### Presentation wording

“After authentication, a conditional accessed = 0 update inside a SQLite
transaction lets only one concurrent request claim the share. The winning
request reads and deletes it.”

If two requests return 200, that is a real replay failure. Save the output and
do not claim one-time access. If responses are 429, wait 65 seconds and retry.

## A4 — Online random key guessing

### Attacker story

The attacker knows a file ID and sends random 256-bit key guesses. The script
hashes each guessed key because that is the format the browser sends.

### Command

~~~bash
python attacks/a4_bruteforce_key.py
~~~

### Passing result

~~~text
Successful guesses: 0
Rate-limit responses (429): 2
VERDICT: PASS
~~~

The exact number of 429 results can be more than two because A3 used two
download attempts earlier. The required facts are zero successful guesses,
at least one 429, and PASS.

### Presentation wording

“Random 256-bit key guesses have negligible chance of matching the
client-generated key. The server additionally throttles repeated online
attempts from an address.”

Immediately after A4, run sleep 65 and wait until it returns.

## A5 — Password-dictionary attack

### Attacker story

The attacker already has the correct key hash but tries common passwords such
as password, 123456, and qwerty.

### Command

Run this only after the 65-second wait following A4:

~~~bash
python attacks/a5_bruteforce_password.py
~~~

### Passing result

~~~text
Successful guesses: 0
Rate-limit responses (429): 2
VERDICT: PASS
~~~

The number of 429 responses may vary, but there must be no 200.

### Presentation wording

“The password is stored with Argon2id and the tested common-password
dictionary did not unlock the share. The endpoint also limits repeated online
requests.”

This does not prove that a weak password can never be guessed. It proves this
specific dictionary and online rate are rejected.

Immediately after A5, run sleep 65 and wait until it returns.

## A6 — Expiry-bypass attempt

### Attacker story

The attacker has a valid key, waits for the TTL to expire, then tries to
download before the background cron cleanup necessarily runs.

### Command

Run this only after the 65-second wait following A5:

~~~bash
python attacks/a6_ttl_bypass.py
~~~

### Passing result

~~~text
Post-expiry response: 404 {"error":"File has expired"}
VERDICT: PASS
~~~

JSON spacing may differ. The required HTTP status is 404.

### Presentation wording

“The download route checks the expiry timestamp before serving the blob. The
link is refused even during the interval before the once-per-minute cron job
removes the file physically.”

If you receive 429, you skipped the required wait after A5. Wait 65 seconds,
then run A6 again.

## A7 — Server-log inspection

### Attacker story

The attacker can read server request logs and searches for the URL fragment
that contains the decryption key.

### Prerequisite

Terminal 1 must still be running this form of command:

~~~bash
node server.js > server.log 2>&1
~~~

### Command

~~~bash
python attacks/a7_log_inspection.py
~~~

### Passing result

~~~text
Fragment marker appears in new server logs: False
Server logged the requested route: True
VERDICT: PASS
~~~

### Presentation wording

“The share key is after the # character. Browsers process URL fragments
locally and do not include them in HTTP requests. The server logs the route
but never the fragment secret.”

If the script cannot find server.log, stop Terminal 1 with Ctrl+C and restart
it using the exact Terminal 1 commands. If the marker appears, preserve that
result: it is a serious logging failure.

## A8 — Man-in-the-middle proxy evaluation

### Attacker story

An on-path attacker reads traffic between the browser and the backend. The
current project uses plain HTTP on localhost, so a proxy can inspect requests
without any TLS certificate.

The automated test looks for three controlled values:

| Controlled value | Expected result | Meaning |
| --- | --- | --- |
| File plaintext marker | false | The file was encrypted before upload. |
| Raw AES key marker | false | The client did not send its AES key. |
| Optional password marker | true | Plain HTTP exposes the password to an on-path attacker. |

The password result is intentionally a security FINDING. It is not a pass.

### Certificates

For this project, do not install a certificate. The traffic is HTTP, so
mitmproxy can inspect it directly. If you later change the system to HTTPS,
an intercepting proxy needs its test certificate installed in a dedicated test
browser profile. That is not needed for this lab.

### Terminal 3: start mitmproxy

Open a third terminal and run:

~~~bash
source /home/vasu/miniconda3/bin/activate security
cd /home/vasu/repos/btp
mitmdump --version
mitmdump -p 8080 -s attacks/a8_mitm_upload.py
~~~

Leave the final command running. You should see HTTP(S) proxy listening at
*:8080. If it says Address already in use, stop the earlier mitmproxy process
with Ctrl+C, then start it again.

### Terminal 2: send one controlled upload through the proxy

Return to Terminal 2 and run:

~~~bash
cd /home/vasu/repos/btp
python attacks/a8_mitm_client.py
~~~

Expected output:

~~~text
Proxied upload response: 200 {"file_id":"..."}
VERDICT: PASS — the controlled upload passed through mitmproxy.
~~~

This PASS only confirms that the upload travelled through the proxy. Read the
evidence file for the security conclusion.

### Read the result

Return to Terminal 3 and press Ctrl+C. In Terminal 2, run:

~~~bash
cat attacks/results/a8_mitm_upload.json
~~~

Expected fields:

~~~json
"plaintext_marker_visible": false
"raw_key_marker_visible": false
"password_visible": true
~~~

The addon intentionally does not save the complete intercepted HTTP body or
the actual password to disk.

### Presentation wording

“The proxy did not see the controlled file plaintext or raw AES key. It did
see the optional upload password because the app sends it in JSON over HTTP.
Argon2id protects the password after it reaches server storage, not while it
travels over the network.”

The fix for an actual network deployment is HTTPS. If the requirement is that
the server must never learn a password either, use a password-authenticated
key exchange such as OPAQUE; hashing it after receipt is not enough.

## Optional: repeat A8 with the browser interface

This is optional. The automated A8 test is the repeatable evidence for your
presentation.

1. Start the frontend in Terminal 4:

   ~~~bash
   cd /home/vasu/repos/btp/frontend
   npm run dev
   ~~~

2. Restart mitmproxy in Terminal 3 using the A8 command above.

3. In a new terminal, find your browser:

   ~~~bash
   command -v google-chrome
   command -v chromium
   ~~~

4. Use whichever command printed a path. For Chrome:

   ~~~bash
   google-chrome --user-data-dir=/tmp/ephemeral-share-proxy-profile --proxy-server=http://127.0.0.1:8080 --proxy-bypass-list='<-loopback>' http://localhost:5173
   ~~~

   For Chromium, replace only google-chrome with chromium. The temporary
   profile protects your normal browser settings. The proxy-bypass option is
   required because browsers normally bypass proxies for localhost.

5. In that temporary browser, create or select a text file whose only content
   is:

   ~~~text
   MITM-PLAINTEXT-SENTINEL-DO-NOT-TRANSMIT
   ~~~

6. On the upload page select that file. Set Password protection to:

   ~~~text
   mitm-password-sentinel
   ~~~

7. Click Encrypt and upload. Terminal 3 will show a POST request to /upload.
   Stop mitmproxy with Ctrl+C and read attacks/results/a8_mitm_upload.json
   from Terminal 2.

For the browser upload, plaintext_marker_visible should be false and
password_visible should be true. The JSON field list has no raw key field.
The automated A8 client supplies the stronger raw-key proof because it uses a
known test key marker.

## Save evidence for your report

Create a folder:

~~~bash
cd /home/vasu/repos/btp
mkdir -p attacks/evidence
~~~

When repeating an attack for presentation evidence, save the terminal output:

~~~bash
python attacks/a1_db_dump.py | tee attacks/evidence/a1_db_dump.txt
~~~

Replace a1_db_dump with each other script name. Keep the required 65-second
waits around A4, A5, and A6. Save the A8 JSON separately:

~~~bash
cp attacks/results/a8_mitm_upload.json attacks/evidence/a8_mitm_upload.json
~~~

| Attack | Passing condition | What to say |
| --- | --- | --- |
| A1 | Raw key and plaintext absent; Argon2id hash present | Database dump does not decrypt the file. |
| A2 | Plaintext absent; wrong AES-GCM key rejected | Stolen blob is unusable without the key. |
| A3 | Exactly one 200 | One-time access survives a concurrent race. |
| A4 | No 200 and at least one 429 | Key guesses fail and are throttled. |
| A5 | No 200 and at least one 429 | This password dictionary fails and is throttled. |
| A6 | 404 after expiry | Expired links are refused by the download route. |
| A7 | Fragment marker is false in log | Share fragments do not reach server logs. |
| A8 | Plaintext/key false; password true | Encryption works, but HTTP exposes upload passwords. |

## Finish

Press Ctrl+C in every terminal that is still running: mitmproxy, frontend, and
backend. Test fixtures have a 60-second TTL. The cron job runs every minute, so
their blobs and rows disappear automatically within about two minutes.

Use this accurate final statement: “The application passed the defined storage,
ciphertext, replay, guessing, expiry, and log-exposure evaluations. The proxy
evaluation found that plain HTTP exposes the optional upload password, so HTTPS
is required before a real network deployment.”
