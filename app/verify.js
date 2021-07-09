fs = require('fs');
moment = require('moment');
crypto = require('crypto');

// Datetime object containing current date and time in the format YYYY-MM-DD hh:mm:ss
now = moment().format("YYYY-MM-DD hh:mm:ss");

method = 'POST'
url = 'https://callback.example.com/04f12bfc'
content = JSON.stringify({'text': 'Hello world'});

// Encode content
content_sha256 = crypto.createHash('sha256').update(content).digest('base64');

headers = {
    'Accepts': 'application/vnd.mcash.api.merchant.v1+json',
    'Content-Type': 'application/json',
    'X-Settle-Merchant': '{merchant_id}',
    'X-Settle-User': '{api_user_id}',
    'X-Settle-Timestamp': now,
    'X-Settle-Content-Digest': 'SHA256=' + content_sha256,
}

// Make all header names uppercase
function allKeysToUpperCase(obj) {
    let output = {};
    for (key in obj) {
        if (Object.prototype.toString.apply(obj[key]) === '[object Object]') {
            output[key.toUpperCase()] = allKeysToUpperCase(obj[key]);
        } else {
            output[key.toUpperCase()] = obj[key];
        }
    }
    return output;
}
headers = allKeysToUpperCase(headers);

// Construct headers string for signature
function sortObjectByKeys(o) {
    return Object.keys(o).sort().reduce((r, k) => (r[k] = o[k], r), {});
}
headers = sortObjectByKeys(headers);
sign_headers = '';
d = '';
for (const property in headers) {
    if (!property.startsWith('X-SETTLE-')) continue;
    // console.log(`${property}: ${headers[property]}`);
    sign_headers += d + property + '=' + headers[property]
    d = '&'
}

// Construct signed message
sign_msg = [method.toUpperCase(), url.toLowerCase(), sign_headers]
sign_msg = sign_msg.join('|')

// Import Key-Pairs
signer = fs.readFileSync('./keys/sample-privkey.pem');
verifier_1 = fs.readFileSync('./keys/sample-pubkey.pem');

// Import other Pub-Key
verifier_2 = fs.readFileSync('./keys/testserver-pub.pem');

// Sign message
createSignature = crypto.createSign('sha256');
createSignature.update(sign_msg);
rsa_signature = createSignature.sign(signer,'base64');

// Construct Auth Header
const rsa_auth_header = 'RSA-SHA256 ' + rsa_signature;

// Verify valid PKCS#1 v1.5 signatures (RSAVP1)
verifySignature_1 = crypto.createVerify('sha256');
verifySignature_1.update(sign_msg);
isVerified_1 = verifySignature_1.verify(verifier_1, rsa_signature,'base64');

console.log('X-Settle-Content-Digest value is: ', content_sha256)
console.log('Headers part of signature message is: ', sign_headers)
console.log('Signature message is: ', sign_msg)
console.log('Authorization header for RSA-SHA256 is: ', rsa_auth_header)

// Verify invalid PKCS#1 v1.5 signatures (RSAVP1)
verifySignature_2 = crypto.createVerify('sha256');
verifySignature_2.update(sign_msg);
isVerified_2 = verifySignature_2.verify(verifier_2, rsa_signature,'base64');

// Log signature verifications
logtext_valid = 'VALID!';
logtext_invalid = 'INVALID';

console.log('First signature should be valid. It\'s', (isVerified_1 === true) ? logtext_valid + ' =)' : logtext_invalid + ' =(');
console.log('Second signature should be invalid. It\'s', (isVerified_2 === true) ? logtext_valid + ' =(' : logtext_invalid + ' =)');