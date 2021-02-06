import { codec, ecc } from './sjcl.js';
import { encrypt, decrypt, serializeEncodedPubKey, encodeMessage, decodeMessage } from './encryptor.js';

const session = async ({ context }) => {
  var str = await context.store.getItem('gp_key');

  if (str) {
    var data = JSON.parse(str);
    console.log('[insomnia-plugin-gp] returning cached session', data);
    return data;
  } else {
    console.log('[insomnia-plugin-gp] generating gp session key');
    var keyPair = ecc.elGamal.generateKeys(256);
    var publicKey = keyPair.pub.get();
    var key = hex.fromBits(publicKey.x.concat(publicKey.y));
    var encodedPublicKey = ans1PubKeyEncoding + key;

    var data = {
      epk: encodedPublicKey,
      pk: codec.base64.fromBits(publicKey.x.concat(publicKey.y)),
      sk: codec.base64.fromBits(keyPair.sec.get()),
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

    var res = await fetch(`${context.request.getEnvironmentVariable('apiUrl')}/config/encryptionKeys`, request);
    if (res.status == 201) {
      var r = await res.json();

      console.log('[insomnia-plugin-gp] key registration response', r);
      data.kxid = r.keyId;

      var serverPubKey = serializeEncodedPubKey(r.serverPublicKey);
      var sharedSecret = keyPair.sec.dhJavaEc(serverPubKey);
      data.ss = encodeMessage(JSON.stringify(sharedSecret));
      data.spk = res.serverPublicKey;

      context.store.setItem('gp_key', JSON.stringify(data));
      console.log('[insomnia-plugin-gp] key registration completed', data);
      return data;
    } else {
      console.error('[insomnia-plugin-gp] error requesting key registration', res);
    }
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

      var ss = JSON.parse(decodeMessage(data.ss));
      var encryptedData = encrypt(requestBody.encryptedData, ss, { kid: data.kxid });
      requestBody.encryptedData = encryptedData;
      body.text = JSON.stringify(requestBody);
    }
  }
};

function transformEncryptedData(sharedSecret, encryptedData) {
  if (sharedSecret === undefined || encryptedData === undefined) return;

  return decrypt(encryptedData, sharedSecret);
}

const decryptResponse = async (context) => {
  // if this isn't json, there isn't much we can do
  if (context.response.getHeader('content-type') === 'application/json') {
    if (context.response.getBody().length > 0) {
      var body = JSON.parse(context.response.getBody());

      const keyData = await session({ context });
      var sharedSecret = JSON.parse(decodeMessage(keyData.ss));

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

export const workspaceActions = [
  {
    label: 'GP - Clear Security Session',
    icon: 'fa-trash',
    action: async (context, models) => {
      context.store.removeItem('gp_key');
    },
  },
];

export const requestHooks = [encryptRequest];
export const responseHooks = [decryptResponse];

export const templateTags = [
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
