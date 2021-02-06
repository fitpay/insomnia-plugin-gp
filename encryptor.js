'use strict';

var sjcl = require('./sjcl');

var ans1PubKeyEncoding = '3059301306072a8648ce3d020106082a8648ce3d03010703420004';
var base64url = sjcl.codec.base64url;
var utf8 = sjcl.codec.utf8String;
var hex = sjcl.codec.hex;

module.exports = {
  ans1PubKeyEncoding: ans1PubKeyEncoding,

  encrypt: function (payload, sharedSecret, options) {
    // generate cek and encrypt with shared secret
    var cek = sjcl.random.randomWords(8);
    var cekIv = sjcl.random.randomWords(3);

    var cekCt = encryptData(sharedSecret, cek, cekIv);
    var encodedCekCt = base64url.fromBits(cekCt.ct);

    // encrypt payload with cek
    var payloadIv = sjcl.random.randomWords(4);
    var encodedPayloadIv = base64url.fromBits(payloadIv);

    var encodedHeader = generateEncodedHeader(cekIv, cekCt.tag, options);
    var encodedHeaderBits = utf8.toBits(encodedHeader);

    var payloadBits = utf8.toBits(JSON.stringify(payload));
    var encryptedPayload = encryptData(cek, payloadBits, payloadIv, encodedHeaderBits);

    // build JWE
    var encodedCipherText = base64url.fromBits(encryptedPayload.ct);
    var encodedAuthTag = base64url.fromBits(encryptedPayload.tag);

    return [encodedHeader, encodedCekCt, encodedPayloadIv, encodedCipherText, encodedAuthTag].join('.');
  },

  decrypt: function (payload, sharedSecret) {
    // parse JWE
    var jwe = payload.split('.');
    var header = decodeHeader(jwe[0]);
    var cekCt = base64url.toBits(jwe[1]);
    var iv = base64url.toBits(jwe[2]);
    var ct = base64url.toBits(jwe[3]);
    var tag = base64url.toBits(jwe[4]);

    // decrypt cekCt
    var cek = decryptData(sharedSecret, cekCt, header.iv, header.tag);

    // decrypt ct
    var aad = sjcl.codec.utf8String.toBits(jwe[0]);
    var dataBits = decryptData(cek, ct, iv, tag, aad);
    var decodedData = utf8.fromBits(dataBits);

    if (header['cty'] === 'JWT') {
      var jwt = decodedData.split('.');
      var payload = decodeMessage(jwt[1]);
      payload = JSON.parse(payload);

      var publicKey = undefined;

      if (payload.iss === 'https://fit-pay.com') {
        //Use server public key
        publicKey = serializeEncodedPubKey(getKKItem('spk'), 'ECDSA');
      } else {
        //Use client public key
        publicKey = serializeEncodedPubKey(getKKItem('epk'), 'ECDSA');
      }

      publicKey.verify(hash.sha256.hash(utf8.toBits(jwt[0] + '.' + jwt[1])), base64url.toBits(jwt[2]));

      return JSON.parse(payload.data);
    } else {
      return JSON.parse(decodedData);
    }
  },

  encodeMessage: function (message) {
    var messageBits = utf8.toBits(message);
    var encodedMessage = base64url.fromBits(messageBits);

    return encodedMessage;
  },

  decodeMessage: function (encodedMessage) {
    var messageBits = sjcl.codec.base64url.toBits(encodedMessage);
    var message = utf8.fromBits(messageBits);

    return message;
  },

  serializeEncodedPubKey: function (encodedServerPubKey, type) {
    var serverPubKey = encodedServerPubKey.replace(ans1PubKeyEncoding, '');
    var serverPubBits = hex.toBits(serverPubKey);
    var serialized = sjcl.codec.base64.fromBits(serverPubBits);

    var algorithm;

    if (type && type === 'ECDSA') {
      algorithm = new sjcl.ecc.ecdsa.publicKey(sjcl.ecc.curves.c256, sjcl.codec.base64.toBits(serialized));
    } else {
      algorithm = new sjcl.ecc.elGamal.publicKey(sjcl.ecc.curves.c256, sjcl.codec.base64.toBits(serialized));
    }

    return algorithm;
  },
};

function encryptData(cipherKey, data, iv, aad) {
  aad = aad || [];
  var cipher = new sjcl.cipher.aes(cipherKey);

  // this and authTag extraction assumes a 128 bit authTag is desired
  var encryptedData = sjcl.mode.gcm.encrypt(cipher, data, iv, aad);

  var authTag = [];
  for (var i = 0; i < 4; i++) {
    authTag.unshift(encryptedData.pop());
  }

  return {
    ct: encryptedData,
    tag: authTag,
  };
}

function generateEncodedHeader(iv, authTag, options) {
  var encodedIv = base64url.fromBits(iv);
  var encodedAuthTag = base64url.fromBits(authTag);

  var header = {
    cty: 'application/json',
    enc: 'A256GCM',
    tag: encodedAuthTag,
    alg: 'A256GCMKW',
    iv: encodedIv,
  };

  if (options) {
    for (var attr in options) {
      header[attr] = options[attr];
    }
  }

  var headerBits = utf8.toBits(JSON.stringify(header));
  var encodedHeader = base64url.fromBits(headerBits);

  return encodedHeader;
}

function decodeMessage(encodedMessage) {
  var messageBits = sjcl.codec.base64url.toBits(encodedMessage);
  var message = sjcl.codec.utf8String.fromBits(messageBits);

  return message;
}

function decodeHeader(encodedHeader) {
  var headerBits = base64url.toBits(encodedHeader);
  var decodedHeader = utf8.fromBits(headerBits);
  var header = JSON.parse(decodedHeader);
  var cekIv = base64url.toBits(header.iv);
  var tag = base64url.toBits(header.tag);
  header.iv = cekIv;
  header.tag = tag;

  return header;
}

function decryptData(cipherKey, data, iv, tag, aad) {
  var cipher = new sjcl.cipher.aes(cipherKey);
  for (var i = 0; i < tag.length; i++) {
    data.push(tag[i]);
  }
  var cek = sjcl.mode.gcm.decrypt(cipher, data, iv, aad);

  return cek;
}
