# Configurable attack-simulation lab

These are attack tools, not tests that know what your application is supposed
to return. They do not contain an expected status code, an expected PASS, an
ephemeral.share key, or an application-specific decision rule.

Each tool records what actually happened: HTTP status, response size, digest,
response preview, timing, captured field names, marker visibility, or storage
artefacts. You interpret those observations against your application's security
requirement. This is how an evaluation remains credible when it is adapted to
another authorised application.

The only target-specific material belongs in a request template or a disposable
test artefact that you create. The generic engines are reusable for another
HTTP application by changing those inputs.

Run these tools only against an application you own or are explicitly
authorised to test. Network-sending tools require the flag
--i-own-this-target.

## Result files

Every run writes a fresh JSON evidence directory:

~~~text
attacks/results/YYYYMMDDTHHMMSSZ_attack_name/result.json
~~~

These evidence files are more important than terminal output. They preserve
the status codes, response hashes, response sizes, timings, and test
configuration used for that specific run. Inspect them with:

~~~bash
find attacks/results -maxdepth 2 -type f | sort
cat attacks/results/PASTE_THE_DIRECTORY_NAME/result.json
~~~

Because replay and spray evidence includes the request template, it can contain
a disposable credential. Use only disposable test shares and passwords, do not
commit the results directory, and delete evidence when your report no longer
needs it.

Proxy tools write JSON Lines files. Read them with:

~~~bash
cat attacks/results/proxy/flows.jsonl
cat attacks/results/tamper/tampered_flows.jsonl
~~~

## Part 1 — Start this application

Use three terminals. Terminal 1 runs the backend. Terminal 2 runs attacks.
Terminal 3 is used only for proxy attacks.

### Terminal 1 — backend

~~~bash
source /home/vasu/miniconda3/bin/activate security
cd /home/vasu/repos/btp/backend
node server.js > server.log 2>&1
~~~

Leave this terminal running. It is intentionally quiet because output goes to
backend/server.log.

### Terminal 2 — attack environment

~~~bash
source /home/vasu/miniconda3/bin/activate security
cd /home/vasu/repos/btp
python -c "import requests, cryptography, mitmproxy; print('security environment ready')"
curl http://localhost:3001/health
~~~

The final command must print:

~~~text
{"status":"ok"}
~~~

### Optional frontend terminal

Several exercises need you to create a disposable share in the browser. Open
another terminal:

~~~bash
cd /home/vasu/repos/btp/frontend
npm run dev
~~~

Open the Local URL printed by Vite, normally http://localhost:5173.

## Part 2 — Create an application request template

A request template is a JSON description of a request that you are authorised
to replay. It is the normal way a reusable attack tool learns where to send
traffic. It is not hardcoded into the tool.

For this application, create a new disposable share in the browser. Copy its
share URL. It looks like:

~~~text
http://localhost:5173/download#id=FILE_ID&key=BASE64URL_KEY
~~~

The string before &key= is FILE_ID. The string after &key= is BASE64URL_KEY.
Do not use a real file or a password you use anywhere else.

In Terminal 2, calculate the credential that the browser sends to the
download API. Replace PASTE_KEY with the exact key value from the link:

~~~bash
python -c "import base64, hashlib; k='PASTE_KEY'; b=base64.urlsafe_b64decode(k+'='*((4-len(k)%4)%4)); print(hashlib.sha256(b).hexdigest())"
~~~

Copy the 64-character output. Create a template file using an editor:

~~~json
{
  "method": "POST",
  "url": "http://localhost:3001/download/PASTE_FILE_ID",
  "headers": {
    "Content-Type": "application/json"
  },
  "json": {
    "key_hash": "PASTE_64_CHARACTER_HASH"
  }
}
~~~

Save it as:

~~~text
attacks/profiles/download_request.json
~~~

If the disposable share has a password, add a password property under json.
This file is a live credential for that disposable share. Never commit it.
After an actual download succeeds, the share is consumed and you must create a
new one for the next attack.

The file attacks/profiles/ephemeral_share_examples.md contains the same setup
with templates for password spraying and identifier enumeration.

## A1 — Storage-compromise forensics

### What an attacker does

The attacker copies the server's storage directory, including database,
database WAL/SHM files, and uploaded blobs. Rather than assuming the database
is safe, this tool scans every file for a known plaintext marker.

### Prepare a controlled marker

In Terminal 2:

~~~bash
printf 'FORENSICS_MARKER_2026_DO_NOT_USE_REAL_DATA' > /tmp/forensics_marker.txt
~~~

Upload that exact small text file through the browser UI as a disposable share.
Do not download it yet.

### Run the attack

~~~bash
python attacks/a1_storage_forensics.py --root backend --marker-file /tmp/forensics_marker.txt
~~~

### Inspect and evaluate

The terminal prints the evidence directory. Open result.json. For every
database, WAL, SHM, and blob file, it records:

- contains_known_plaintext
- SHA-256
- sample entropy
- first bytes as hexadecimal
- whether it is a SQLite database

For encrypted storage, the marker should be absent from database files and
from the blob. If it appears in a blob, database, WAL, or SHM file, you have
concrete evidence that plaintext leaked into server storage.

This is stronger than merely checking the database schema because it searches
the actual storage artefacts an attacker would copy.

## A2 — Stolen-blob forensics

### What an attacker does

The attacker steals a particular server-side blob and examines it without
assuming a cipher, nonce format, or implementation language.

### Prepare

Use the FILE_ID from your disposable share URL. For this application its blob
path is:

~~~text
backend/uploads/FILE_ID.bin
~~~

Create a known plaintext file first, upload it, and keep the original local
file. For example:

~~~bash
printf 'BLOB_MARKER_2026' > /tmp/blob_marker.txt
~~~

### Run the attack

Replace FILE_ID:

~~~bash
python attacks/a2_blob_forensics.py --blob backend/uploads/FILE_ID.bin --known-plaintext-file /tmp/blob_marker.txt
~~~

### Inspect and evaluate

The evidence records whether the original bytes occur in the blob, whether
common cleartext file signatures occur, entropy, a digest, and a hex prefix.

For a properly encrypted blob, the known plaintext should not occur and the
blob normally has high entropy. High entropy alone is not proof of encryption;
it is only a forensic indicator. If known plaintext or an original PDF/PNG/ZIP
signature occurs unexpectedly, preserve result.json and treat it as a
confidentiality finding.

## A3 — Concurrent replay race

### What an attacker does

The attacker obtains one valid request and sends it simultaneously from several
workers, attempting to exploit a check-then-delete race.

### Run the attack

Create a new disposable share and new download_request.json. Then run:

~~~bash
python attacks/a3_replay_race.py --request attacks/profiles/download_request.json --workers 8 --i-own-this-target
~~~

### Inspect and evaluate

The tool does not decide that 200 or 404 is good. It records one observation
per worker plus response clusters. Look at:

- status
- elapsed_ms
- content_length
- body_sha256
- body_preview

For a one-time share requirement, count the workers that received the actual
file response. A secure result has one such response. Two or more independent
workers receiving the same protected resource is evidence of a replay race.

For this application, a response carrying encrypted_blob is the file response.
You can search the saved JSON:

~~~bash
grep -n encrypted_blob attacks/results/PASTE_A3_DIRECTORY/result.json
~~~

## A4 — Authorised online credential or token spray

### What an attacker does

The attacker tries a supplied candidate list against a supplied request
placeholder. This is a generic credential, key-hash, token, OTP, or API-key
spray engine. It does not include a hardcoded password dictionary and it does
not decide which response means success.

### Prepare the request and wordlist

Create a disposable password-protected share. Make a copy of
download_request.json named spray_request.json. Add or replace its password:

~~~json
"password": "{{GUESS}}"
~~~

Create your own small authorised candidate file:

~~~bash
cat > /tmp/test_candidates.txt <<'EOF'
incorrect-one
incorrect-two
incorrect-three
EOF
~~~

The command above is only an example test corpus. In a legitimate assessment,
the wordlist must be approved by the system owner and chosen for the threat
model. It is not embedded in the attack source.

### Run the attack

~~~bash
python attacks/a4_request_spray.py --request attacks/profiles/spray_request.json --wordlist /tmp/test_candidates.txt --max-attempts 3 --delay 1 --i-own-this-target
~~~

### Inspect and evaluate

The tool saves a SHA-256 of each candidate rather than the candidate text. It
groups responses by status, length, and body digest. Review result.json:

~~~bash
cat attacks/results/PASTE_A4_DIRECTORY/result.json
~~~

Different clusters are concrete anomalies. For example, if most candidates
produce one body digest but one produces a different response containing file
data or a different authorization state, investigate that candidate. If all
responses are identical, the corpus found no response-level evidence of a
valid credential. If the application returns 429, that is observed throttling,
not an assumed pass.

## A5 — Delayed replay for TTL or revocation

### What an attacker does

The attacker retains a captured valid request and sends it only after the
resource should have expired or been revoked.

### Run the attack

Create a disposable share with a known TTL. Save the valid request template.
For this UI the shortest selectable TTL is five minutes. To test expiry, wait
301 seconds:

~~~bash
python attacks/a5_delayed_replay.py --request attacks/profiles/download_request.json --wait-seconds 301 --i-own-this-target
~~~

### Inspect and evaluate

The result contains the actual post-wait response. To make a proper
comparison, create a separate disposable share with the same settings and run:

~~~bash
python attacks/a5_delayed_replay.py --request attacks/profiles/download_request.json --wait-seconds 0 --i-own-this-target
~~~

Compare the pre-expiry and post-expiry result.json files. Your security
requirement determines the expected difference. For an expiring share, the
post-expiry response must not contain the protected resource. The tool does
not assume a particular error code.

## A6 — Identifier enumeration

### What an attacker does

The attacker probes identifiers and looks for response differences that reveal
which IDs exist, have expired, or belong to another user.

### Prepare

Copy a request template that queries object metadata. For this application:

~~~json
{
  "method": "GET",
  "url": "http://localhost:3001/file-info/{{ID}}",
  "headers": {}
}
~~~

Save it as attacks/profiles/identifier_request.json. Make a list containing
only authorised test IDs: one currently existing disposable FILE_ID and a few
random UUIDs you created yourself.

~~~bash
python -c "import uuid; [print(uuid.uuid4()) for _ in range(5)]" > /tmp/test_ids.txt
~~~

Edit /tmp/test_ids.txt and add the known disposable FILE_ID as its first line.

### Run the attack

~~~bash
python attacks/a6_identifier_enumeration.py --request attacks/profiles/identifier_request.json --identifiers /tmp/test_ids.txt --max-attempts 6 --i-own-this-target
~~~

### Inspect and evaluate

The tool reports response clusters. Compare status, length, digest, and timing
between your known-valid ID and random IDs. Different responses are factual
enumeration signals. Whether that is acceptable depends on your system: public
shares may intentionally say that an object exists, while private objects
usually should not expose distinguishable existence information.

## A7 — Generic on-path traffic capture

### What an attacker does

The attacker runs a local intercepting proxy and captures actual traffic. The
proxy does not know your application's expected result. It records the fields
and bytes it actually sees.

### Terminal 3: start capture

~~~bash
source /home/vasu/miniconda3/bin/activate security
cd /home/vasu/repos/btp
mitmdump -p 8080 -s attacks/a7_mitm_capture.py --set evidence_dir=attacks/results/proxy --set url_regex=/upload --set marker=TRANSPORT_MARKER
~~~

### Browser setup

Start the frontend if needed. Then launch a temporary Chrome profile through
the proxy:

~~~bash
google-chrome --user-data-dir=/tmp/ephemeral-share-proxy-profile --proxy-server=http://127.0.0.1:8080 --proxy-bypass-list='<-loopback>' http://localhost:5173
~~~

Use chromium in place of google-chrome if that is your browser command.

In the temporary browser, upload a disposable text file whose content includes
TRANSPORT_MARKER. You can also choose a disposable password.

After uploading, stop mitmdump with Ctrl+C. In Terminal 2 inspect:

~~~bash
cat attacks/results/proxy/flows.jsonl
~~~

### Evaluate

The capture contains actual request JSON field names, sensitive-looking field
names, request/response hashes, sizes, status codes, and whether the marker
appeared. With encrypted client-side upload, the plaintext marker should not
be in the request body. If it is, that is direct plaintext-in-transit evidence.

For this project HTTP has no TLS. Do not install a certificate: mitmproxy can
read the traffic directly. If you later add HTTPS, a test browser must trust
the mitmproxy certificate before traffic can be intercepted.

## A8 — Active ciphertext-tampering proxy

### What an attacker does

The attacker changes a JSON field during transit, then observes whether the
server accepts it and whether the recipient detects corruption. This is an
availability and integrity attack, not a confidentiality attack.

### Terminal 3: start the tampering proxy

~~~bash
source /home/vasu/miniconda3/bin/activate security
cd /home/vasu/repos/btp
mitmdump -p 8080 -s attacks/a8_mitm_tamper.py --set evidence_dir=attacks/results/tamper --set url_regex=/upload --set json_field=encrypted_blob
~~~

### Browser setup and action

Launch the temporary proxied browser using the A7 browser command. Upload a
new disposable file and copy the resulting share URL. The proxy changes the
first character of the actual encrypted_blob field while preserving its JSON
shape.

Stop mitmdump and inspect:

~~~bash
cat attacks/results/tamper/tampered_flows.jsonl
~~~

Then open the copied share URL in a normal browser and attempt the download.

### Evaluate

The JSONL file proves whether the tampering proxy changed a request and records
the server's actual response. The recipient-side result tells you whether the
application detects corruption. For authenticated encryption, the recipient
should see a decryption or authentication failure, not silently receive a
modified plaintext. If a changed encrypted blob decrypts to changed plaintext
without an error, preserve all evidence: that is a serious integrity failure.

The server may still return an upload success response because it cannot
decrypt client-side ciphertext. That does not mean tampering succeeded
cryptographically; it shows a network attacker can cause availability loss
when HTTP is used.

## How to defend this methodology

In your presentation, say:

“The attack engines are target-independent. Target-specific values are
supplied as disposable request templates and markers. Each run writes raw
observations such as HTTP status, body hashes, timing, and captured traffic.
We interpreted those observations against the stated security property rather
than encoding an expected pass into the attack script.”

Do not say that every attack passed. State the concrete observation. In
particular, A7 and A8 will demonstrate that plain HTTP lets an on-path attacker
observe and modify transport traffic. HTTPS is required before deployment on
an untrusted network.
