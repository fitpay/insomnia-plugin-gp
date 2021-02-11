var sjcl = require('./sjcl');
var encryptor = require('./encryptor');

const session = async ({ context }) => {
  var str = await context.store.getItem('gp-api:key');

  // if we have a cached key, let's make sure it's still useable
  if (str) {
    var data = JSON.parse(str);

    // if the server gave us an expirationTs, then use that to determine if the key is still good
    // if not, then validate the key is still good!
    if (data.expirationTsEpoch) {
      var expirationTs = new Date(date.expirationTsEpoch);

      // use a bit of a buffer (60s) to account for clock drift
      if (new Date().getTime() - 60000 < expirationTs) {
        console.log('[insomnia-plugin-gp] returning cached session', data);
        return data;
      } else {
        context.store.removeItem('gp-api:key');
      }
    } else {
      // no expirationTs returned by the server, so force a validation to see if the key is still good
      var res = await fetch(`${context.request.getEnvironmentVariable('apiUrl')}/config/encryptionKeys/${data.kxid}`);
      if (res.status == 200) {
        console.log('[insomnia-plugin-gp] returning cached session', data);
        return data;
      } else {
        context.store.removeItem('gp-api:key');
      }
    }
  }

  // if we get here, the key either hasn't been created/registered or the current key is no longer
  // considered good.
  console.log('[insomnia-plugin-gp] generating gp session key');
  var keyPair = sjcl.ecc.elGamal.generateKeys(256);
  var publicKey = keyPair.pub.get();
  var key = sjcl.codec.hex.fromBits(publicKey.x.concat(publicKey.y));
  var encodedPublicKey = encryptor.ans1PubKeyEncoding + key;

  var data = {
    epk: encodedPublicKey,
    pk: sjcl.codec.base64.fromBits(publicKey.x.concat(publicKey.y)),
    sk: sjcl.codec.base64.fromBits(keyPair.sec.get()),
    timeValidated: new Date().getTime(),
  };

  const request = {
    method: 'post',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      clientPublicKey: data.epk,
    }),
  };

  console.log('[insomnia-plugin-gp] registering gp session key');
  var res = await fetch(`${context.request.getEnvironmentVariable('apiUrl')}/config/encryptionKeys`, request);
  if (res.status == 201) {
    var r = await res.json();

    console.log('[insomnia-plugin-gp] key registration response', r);
    data.kxid = r.keyId;

    var serverPubKey = encryptor.serializeEncodedPubKey(r.serverPublicKey);
    var sharedSecret = keyPair.sec.dhJavaEc(serverPubKey);
    data.ss = encryptor.encodeMessage(JSON.stringify(sharedSecret));
    data.spk = res.serverPublicKey;
    data.expirationTsEpoch = res.expirationTsEpoch;

    context.store.setItem('gp-api:key', JSON.stringify(data));
    console.log('[insomnia-plugin-gp] key registration completed', data);
    return data;
  } else {
    console.error('[insomnia-plugin-gp] error requesting key registration', res);
  }
};

const encryptRequest = async (context) => {
  const data = await session({ context });

  if (data.kxid) {
    context.request.setHeader('fp-key-id', data.kxid);
  }

  var body = context.request.getBody();
  if (body.text) {
    var requestBody = JSON.parse(body.text);

    if (requestBody.encryptedData) {
      console.log('[insomnia-plugin-gp] encrypt request: ', data.kxid);

      var ss = JSON.parse(encryptor.decodeMessage(data.ss));
      var encryptedData = encryptor.encrypt(requestBody.encryptedData, ss, { kid: data.kxid });
      requestBody.encryptedData = encryptedData;
      body.text = JSON.stringify(requestBody);
    }
  }
};

function transformEncryptedData(sharedSecret, encryptedData) {
  if (sharedSecret === undefined || encryptedData === undefined) return;

  return encryptor.decrypt(encryptedData, sharedSecret);
}

const decryptResponse = async (context) => {
  // if this isn't json, there isn't much we can do
  if (context.response.getHeader('content-type') === 'application/json') {
    if (context.response.getBody().length > 0) {
      var body = JSON.parse(context.response.getBody());

      const keyData = await session({ context });
      var sharedSecret = JSON.parse(encryptor.decodeMessage(keyData.ss));

      if (body.encryptedData) {
        body.encryptedData = transformEncryptedData(sharedSecret, body.encryptedData);
      }

      if (body.results) {
        for (var i = 0; i < body.results.length; i++) {
          if (body.results[i].encryptedData) {
            body.results[i].encryptedData = transformEncryptedData(sharedSecret, body.results[i].encryptedData);
          }
        }
      }

      context.response.setBody(JSON.stringify(body));
    }
  }
};

module.exports.workspaceActions = [
  {
    label: 'GP - Clear Security Session',
    icon: 'fa-trash',
    action: async (context, models) => {
      context.store.removeItem('gp-api:key');
    },
  },
];

module.exports.requestHooks = [encryptRequest];
module.exports.responseHooks = [decryptResponse];

module.exports.templateTags = [
  {
    name: 'gpKeyId',
    displayName: 'gpKeyId',
    description: 'Current Garmin Pay session keyId, if exists',
    args: [],
    async run(context) {
      const keyData = await session({ context });
      return keyData.kxid;
    },
  },
];
