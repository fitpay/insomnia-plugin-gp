const sjcl = require('./sjcl.js');
const encryptor = require('./encryptor.js');

var ans1PubKeyEncoding = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';
var hex = sjcl.codec.hex;

function encodeMessage(message) {
    var messageBits = sjcl.codec.utf8String.toBits(message);
    var encodedMessage = sjcl.codec.base64url.fromBits(messageBits);

    return encodedMessage;
}

function decodeMessage(encodedMessage) {
    var messageBits = sjcl.codec.base64url.toBits(encodedMessage);
    var message = sjcl.codec.utf8String.fromBits(messageBits);

    return message;
  }

function serializeEncodedPubKey(encodedServerPubKey, type) {
    var serverPubKey = encodedServerPubKey.replace(ans1PubKeyEncoding, '');
    var serverPubBits = hex.toBits(serverPubKey);
    var serialized = sjcl.codec.base64.fromBits(serverPubBits);

    var algorithm;

    if (type && type === 'ECDSA') {
      algorithm = new sjcl.ecc.ecdsa.publicKey(
        sjcl.ecc.curves.c256,
        sjcl.codec.base64.toBits(serialized)
      );
    } else {
      algorithm = new sjcl.ecc.elGamal.publicKey(
        sjcl.ecc.curves.c256,
        sjcl.codec.base64.toBits(serialized)
      );
    }

    return algorithm;
  }


const session = async ({context}) => {
    var str = await context.store.getItem('gp_key');

    if (str) {
        var data = JSON.parse(str);
        console.log('returning cached session', data);
        return data;
    } else {
        console.log('generating session key');
        var keyPair = sjcl.ecc.elGamal.generateKeys(256);
        var publicKey = keyPair.pub.get();
        var key = hex.fromBits(publicKey.x.concat(publicKey.y));
        var encodedPublicKey = ans1PubKeyEncoding + key;

        var data = {
            epk: encodedPublicKey,
            pk: sjcl.codec.base64.fromBits(publicKey.x.concat(publicKey.y)),
            sk: sjcl.codec.base64.fromBits(keyPair.sec.get())
        };

        const request = {
            method: "post",
            headers: {
                "content-type": "application/json",
                "accept": "application/json"
            },
            body: JSON.stringify({
                "clientPublicKey": data.epk
            })
        };

        var res = await fetch(`${context.request.getEnvironmentVariable('apiUrl')}/config/encryptionKeys`, request);
        if (res.status == 201) {
            var r = await res.json();

            console.log("key registration response", r);
            data.kxid = r.keyId;

            var serverPubKey = serializeEncodedPubKey(r.serverPublicKey);
            var sharedSecret = keyPair.sec.dhJavaEc(serverPubKey);
            data.ss = encodeMessage(JSON.stringify(sharedSecret));
            data.spk = res.serverPublicKey;
    
            context.store.setItem('gp_key', JSON.stringify(data));
            console.log("key registration completed", data);
            return data;
        } else {
            console.error("error requesting key registration", res);
        }
    }
}

const encryptRequest = async(context) => {
    const data = await session({context});
    
    if (data.kxid) {
        context.request.setHeader('fp-key-id', data.kxid);
    }

    var body = context.request.getBody();
    if (body.text) {
        var requestBody = JSON.parse(body.text);

        if (requestBody.encryptedData) {
            console.log('encrypt request: ', data.kxid);

            var ss = JSON.parse(decodeMessage(data.ss));
            var encryptedData = encryptor.encrypt(
                requestBody.encryptedData,
                ss,
                { kid: data.kxid }
            );
            requestBody.encryptedData = encryptedData;
            console.log('new body', requestBody);
            body.text = JSON.stringify(requestBody);
        }
    }
}

const decryptResponse = async(context) => {
    // if this isn't json, there isn't much we can do
    if (context.response.getHeader('content-type') === 'application/json') {
        if (context.response.getBody().length > 0) {
            var body = JSON.parse(context.response.getBody());
            if (body.encryptedData) {
                const data = await session({context});
                var ss = JSON.parse(decodeMessage(data.ss));
                var payload = encryptor.decrypt(body.encryptedData, ss);
                console.log("payload", payload);
        
                body.encryptedData = payload;
                context.response.setBody(JSON.stringify(body));
            }
        }
    }
}

module.exports.workspaceActions = [{
    label: 'GP - Clear Security Session',
    icon: 'fa-trash',
    action: async (context, models) => {
        context.store.removeItem('gp_key');
    },
}];

module.exports.requestHooks = [encryptRequest];
module.exports.responseHooks = [decryptResponse];