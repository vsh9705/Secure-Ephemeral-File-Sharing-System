# Creating request templates for ephemeral.share

The attack engines never contain this application's credentials or expected
outcomes. They need a request template produced from your own disposable test
share.

For a download replay or TTL test, create a disposable share in the browser.
The share URL has this form:

    http://localhost:5173/download#id=FILE_ID&key=BASE64URL_KEY

Calculate the download credential in the security environment:

    python -c "import base64, hashlib; k='PASTE_KEY_AFTER_key_EQUALS_HERE'; b=base64.urlsafe_b64decode(k+'='*((4-len(k)%4)%4)); print(hashlib.sha256(b).hexdigest())"

Create a file named attacks/profiles/download_request.json with the values you
just obtained:

    {
      "method": "POST",
      "url": "http://localhost:3001/download/PASTE_FILE_ID_HERE",
      "headers": {"Content-Type": "application/json"},
      "json": {"key_hash": "PASTE_HASH_HERE"}
    }

If the share has a password, add a password field to the json object. The
request template is a disposable credential: never commit it or use a real
password.

For identifier enumeration, copy that file to identifier_request.json and
replace the UUID in url with {{ID}}. Create a text file containing only
authorised test UUIDs. Include one UUID for a currently existing disposable
share and several random UUIDs you generated yourself.

For a spray test, copy the download request to spray_request.json and replace
the password value with {{GUESS}}. Supply your own small wordlist of test
candidates. The engine reports response clusters; it does not decide which
cluster means success.
