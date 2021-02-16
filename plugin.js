var sjcl = require('./sjcl');
var encryptor = require('./encryptor');

var defaultConfiguration = {
  apiUrlEnvironmentVariable: 'apiUrl',
  keyExpirationBuffer: 60000,
};

async function configuration(context) {
  const str = await context.store.getItem('gp-api:config');

  var oldConfig = undefined;
  if (str) {
    oldConfig = JSON.parse(str);
  }

  return oldConfig || defaultConfiguration;
}

async function changeConfiguration(context) {
  const oldConfig = await context.store.getItem('gp-api:config');

  // Prompt for the configuration
  try {
    var config = await context.app.prompt('GP - Configuration', {
      label: 'JSON string',
      defaultValue: oldConfig || JSON.stringify(defaultConfiguration),
      submitName: 'Save',
      cancelable: true,
    });
  } catch (e) {
    return false;
  }

  // Validate the JSON config
  try {
    JSON.parse(config);
  } catch (e) {
    context.app.alert('Invalid JSON!', 'Error: ' + e.message);
    return false;
  }

  await context.store.setItem('gp-api:config', config);
}

async function session(context) {
  var str = await context.store.getItem('gp-api:key');

  // if we have a cached key, let's make sure it's still useable
  if (str) {
    var data = JSON.parse(str);
    var config = await configuration(context);

    // if the server gave us an expirationTs, then use that to determine if the key is still good
    // if not, then validate the key is still good!

    if (data.expirationTsEpoch) {
      var expirationTs = new Date(data.expirationTsEpoch);

      // use a bit of a buffer (60s) to account for clock drift
      if (new Date().getTime() - config.keyExpirationBuffer < expirationTs) {
        console.log('[insomnia-plugin-gp] returning cached session', data);
        return data;
      } else {
        context.store.removeItem('gp-api:key');
      }
    } else {
      // no expirationTs returned by the server, so force a validation to see if the key is still good
      console.log('[insomnia-plugin-gp] no expirationTs returned by server, verifying key', data);
      var res = await fetch(
        `${context.request.getEnvironmentVariable(config.apiUrlEnvironmentVariable)}/config/encryptionKeys/${data.kxid}`
      );
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

  var config = await configuration(context);

  console.log('[insomnia-plugin-gp] registering gp session key');
  var res = await fetch(
    `${context.request.getEnvironmentVariable(config.apiUrlEnvironmentVariable)}/config/encryptionKeys`,
    request
  );

  if (res.status == 201) {
    var r = await res.json();

    console.log('[insomnia-plugin-gp] key registration response', r);
    data.kxid = r.keyId;
    data.expirationTsEpoch = r.expirationTsEpoch;

    var serverPubKey = encryptor.serializeEncodedPubKey(r.serverPublicKey);
    var sharedSecret = keyPair.sec.dhJavaEc(serverPubKey);
    data.ss = encryptor.encodeMessage(JSON.stringify(sharedSecret));
    data.spk = res.serverPublicKey;

    context.store.setItem('gp-api:key', JSON.stringify(data));
    console.log('[insomnia-plugin-gp] key registration completed', data);
    return data;
  } else {
    console.error('[insomnia-plugin-gp] error requesting key registration', res);
  }
}

const encryptRequest = async (context) => {
  const data = await session(context);

  if (data && data.kxid) {
    context.request.setHeader('fp-key-id', data.kxid);
  }

  var body = context.request.getBody();
  if (body.text) {
    var requestBody = JSON.parse(body.text);

    if (requestBody.encryptedData) {
      var ss = (data && data.ss) ? JSON.parse(encryptor.decodeMessage(data.ss)) : undefined;

      if (ss) {
        console.log('[insomnia-plugin-gp] encrypt request: ', data.kxid);

        var encryptedData = encryptor.encrypt(requestBody.encryptedData, ss, { kid: data.kxid });
        requestBody.encryptedData = encryptedData;

        body.text = JSON.stringify(requestBody);
      } else {
        console.log('[insomnia-plugin-gp] encryption skipped, no shared secret available', keyData);
      }
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

      const keyData = await session(context);
      var sharedSecret = (keyData && keyData.ss) ? JSON.parse(encryptor.decodeMessage(keyData.ss)) : undefined;

      if (sharedSecret) {
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
      } else {
        console.log('[insomnia-plugin-gp] decryption skipped, no shared secret available', keyData);
      }
    } 
  }
};

module.exports.workspaceActions = [
  {
    label: 'GP - Clear Security Session',
    icon: 'fa-trash',
    action: async (context) => {
      context.store.removeItem('gp-api:key');
    },
  },
  {
    label: 'GP - Configure',
    icon: 'fa-cogs',
    action: async (context) => {
      changeConfiguration(context);
    },
  },
  {
    label: 'GP - Reset to Defaults',
    icon: 'fa-undo',
    action: async (context) => {
      context.store.removeItem('gp-api:config');
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
      var str = await context.store.getItem('gp-api:key');
      if (str) {
        var keyData = JSON.parse(str);
        return keyData.kxid;
      }
    },
  },
];
