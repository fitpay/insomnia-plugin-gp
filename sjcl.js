// Source: https://github.com/bitwiseshiftleft/sjcl

/*
SJCL is open. You can use, modify and redistribute it under a BSD
license or under the GNU GPL, version 2.0.

---------------------------------------------------------------------

http://opensource.org/licenses/BSD-2-Clause

Copyright (c) 2009-2015, Emily Stark, Mike Hamburg and Dan Boneh at
Stanford University. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---------------------------------------------------------------------

http://opensource.org/licenses/GPL-2.0

The Stanford Javascript Crypto Library (hosted here on GitHub) is a
project by the Stanford Computer Security Lab to build a secure,
powerful, fast, small, easy-to-use, cross-browser library for
cryptography in Javascript.

Copyright (c) 2009-2015, Emily Stark, Mike Hamburg and Dan Boneh at
Stanford University.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*/

('use strict');
function q(a) {
  throw a;
}
var t = void 0,
  u = !0,
  v = !1;
var sjcl = {
  cipher: {},
  hash: {},
  keyexchange: {},
  mode: {},
  misc: {},
  codec: {},
  exception: {
    corrupt: function (a) {
      this.toString = function () {
        return 'CORRUPT: ' + this.message;
      };
      this.message = a;
    },
    invalid: function (a) {
      this.toString = function () {
        return 'INVALID: ' + this.message;
      };
      this.message = a;
    },
    bug: function (a) {
      this.toString = function () {
        return 'BUG: ' + this.message;
      };
      this.message = a;
    },
    notReady: function (a) {
      this.toString = function () {
        return 'NOT READY: ' + this.message;
      };
      this.message = a;
    },
  },
};
'undefined' !== typeof module && module.exports && (module.exports = sjcl);
'function' === typeof define &&
  define([], function () {
    return sjcl;
  });
sjcl.cipher.aes = function (a) {
  this.t[0][0][0] || this.Q();
  var b,
    c,
    d,
    e,
    f = this.t[0][4],
    g = this.t[1];
  b = a.length;
  var h = 1;
  4 !== b && 6 !== b && 8 !== b && q(new sjcl.exception.invalid('invalid aes key size'));
  this.d = [(d = a.slice(0)), (e = [])];
  for (a = b; a < 4 * b + 28; a++) {
    c = d[a - 1];
    if (0 === a % b || (8 === b && 4 === a % b))
      (c = (f[c >>> 24] << 24) ^ (f[(c >> 16) & 255] << 16) ^ (f[(c >> 8) & 255] << 8) ^ f[c & 255]),
        0 === a % b && ((c = (c << 8) ^ (c >>> 24) ^ (h << 24)), (h = (h << 1) ^ (283 * (h >> 7))));
    d[a] = d[a - b] ^ c;
  }
  for (b = 0; a; b++, a--)
    (c = d[b & 3 ? a : a - 4]),
      (e[b] =
        4 >= a || 4 > b
          ? c
          : g[0][f[c >>> 24]] ^ g[1][f[(c >> 16) & 255]] ^ g[2][f[(c >> 8) & 255]] ^ g[3][f[c & 255]]);
};
sjcl.cipher.aes.prototype = {
  encrypt: function (a) {
    return w(this, a, 0);
  },
  decrypt: function (a) {
    return w(this, a, 1);
  },
  t: [
    [[], [], [], [], []],
    [[], [], [], [], []],
  ],
  Q: function () {
    var a = this.t[0],
      b = this.t[1],
      c = a[4],
      d = b[4],
      e,
      f,
      g,
      h = [],
      k = [],
      l,
      n,
      m,
      p;
    for (e = 0; 0x100 > e; e++) k[(h[e] = (e << 1) ^ (283 * (e >> 7))) ^ e] = e;
    for (f = g = 0; !c[f]; f ^= l || 1, g = k[g] || 1) {
      m = g ^ (g << 1) ^ (g << 2) ^ (g << 3) ^ (g << 4);
      m = (m >> 8) ^ (m & 255) ^ 99;
      c[f] = m;
      d[m] = f;
      n = h[(e = h[(l = h[f])])];
      p = (0x1010101 * n) ^ (0x10001 * e) ^ (0x101 * l) ^ (0x1010100 * f);
      n = (0x101 * h[m]) ^ (0x1010100 * m);
      for (e = 0; 4 > e; e++) (a[e][f] = n = (n << 24) ^ (n >>> 8)), (b[e][m] = p = (p << 24) ^ (p >>> 8));
    }
    for (e = 0; 5 > e; e++) (a[e] = a[e].slice(0)), (b[e] = b[e].slice(0));
  },
};
function w(a, b, c) {
  4 !== b.length && q(new sjcl.exception.invalid('invalid aes block size'));
  var d = a.d[c],
    e = b[0] ^ d[0],
    f = b[c ? 3 : 1] ^ d[1],
    g = b[2] ^ d[2];
  b = b[c ? 1 : 3] ^ d[3];
  var h,
    k,
    l,
    n = d.length / 4 - 2,
    m,
    p = 4,
    s = [0, 0, 0, 0];
  h = a.t[c];
  a = h[0];
  var r = h[1],
    z = h[2],
    A = h[3],
    B = h[4];
  for (m = 0; m < n; m++)
    (h = a[e >>> 24] ^ r[(f >> 16) & 255] ^ z[(g >> 8) & 255] ^ A[b & 255] ^ d[p]),
      (k = a[f >>> 24] ^ r[(g >> 16) & 255] ^ z[(b >> 8) & 255] ^ A[e & 255] ^ d[p + 1]),
      (l = a[g >>> 24] ^ r[(b >> 16) & 255] ^ z[(e >> 8) & 255] ^ A[f & 255] ^ d[p + 2]),
      (b = a[b >>> 24] ^ r[(e >> 16) & 255] ^ z[(f >> 8) & 255] ^ A[g & 255] ^ d[p + 3]),
      (p += 4),
      (e = h),
      (f = k),
      (g = l);
  for (m = 0; 4 > m; m++)
    (s[c ? 3 & -m : m] =
      (B[e >>> 24] << 24) ^ (B[(f >> 16) & 255] << 16) ^ (B[(g >> 8) & 255] << 8) ^ B[b & 255] ^ d[p++]),
      (h = e),
      (e = f),
      (f = g),
      (g = b),
      (b = h);
  return s;
}
sjcl.bitArray = {
  bitSlice: function (a, b, c) {
    a = sjcl.bitArray.aa(a.slice(b / 32), 32 - (b & 31)).slice(1);
    return c === t ? a : sjcl.bitArray.clamp(a, c - b);
  },
  extract: function (a, b, c) {
    var d = Math.floor((-b - c) & 31);
    return (
      (((b + c - 1) ^ b) & -32 ? (a[(b / 32) | 0] << (32 - d)) ^ (a[(b / 32 + 1) | 0] >>> d) : a[(b / 32) | 0] >>> d) &
      ((1 << c) - 1)
    );
  },
  concat: function (a, b) {
    if (0 === a.length || 0 === b.length) return a.concat(b);
    var c = a[a.length - 1],
      d = sjcl.bitArray.getPartial(c);
    return 32 === d ? a.concat(b) : sjcl.bitArray.aa(b, d, c | 0, a.slice(0, a.length - 1));
  },
  bitLength: function (a) {
    var b = a.length;
    return 0 === b ? 0 : 32 * (b - 1) + sjcl.bitArray.getPartial(a[b - 1]);
  },
  clamp: function (a, b) {
    if (32 * a.length < b) return a;
    a = a.slice(0, Math.ceil(b / 32));
    var c = a.length;
    b &= 31;
    0 < c && b && (a[c - 1] = sjcl.bitArray.partial(b, a[c - 1] & (2147483648 >> (b - 1)), 1));
    return a;
  },
  partial: function (a, b, c) {
    return 32 === a ? b : (c ? b | 0 : b << (32 - a)) + 0x10000000000 * a;
  },
  getPartial: function (a) {
    return Math.round(a / 0x10000000000) || 32;
  },
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) return v;
    var c = 0,
      d;
    for (d = 0; d < a.length; d++) c |= a[d] ^ b[d];
    return 0 === c;
  },
  aa: function (a, b, c, d) {
    var e;
    e = 0;
    for (d === t && (d = []); 32 <= b; b -= 32) d.push(c), (c = 0);
    if (0 === b) return d.concat(a);
    for (e = 0; e < a.length; e++) d.push(c | (a[e] >>> b)), (c = a[e] << (32 - b));
    e = a.length ? a[a.length - 1] : 0;
    a = sjcl.bitArray.getPartial(e);
    d.push(sjcl.bitArray.partial((b + a) & 31, 32 < b + a ? c : d.pop(), 1));
    return d;
  },
  n: function (a, b) {
    return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
  },
  byteswapM: function (a) {
    var b, c;
    for (b = 0; b < a.length; ++b)
      (c = a[b]), (a[b] = (c >>> 24) | ((c >>> 8) & 0xff00) | ((c & 0xff00) << 8) | (c << 24));
    return a;
  },
};
sjcl.codec.utf8String = {
  fromBits: function (a) {
    var b = '',
      c = sjcl.bitArray.bitLength(a),
      d,
      e;
    for (d = 0; d < c / 8; d++) 0 === (d & 3) && (e = a[d / 4]), (b += String.fromCharCode(e >>> 24)), (e <<= 8);
    return decodeURIComponent(escape(b));
  },
  toBits: function (a) {
    a = unescape(encodeURIComponent(a));
    var b = [],
      c,
      d = 0;
    for (c = 0; c < a.length; c++) (d = (d << 8) | a.charCodeAt(c)), 3 === (c & 3) && (b.push(d), (d = 0));
    c & 3 && b.push(sjcl.bitArray.partial(8 * (c & 3), d));
    return b;
  },
};
sjcl.codec.hex = {
  fromBits: function (a) {
    var b = '',
      c;
    for (c = 0; c < a.length; c++) b += ((a[c] | 0) + 0xf00000000000).toString(16).substr(4);
    return b.substr(0, sjcl.bitArray.bitLength(a) / 4);
  },
  toBits: function (a) {
    var b,
      c = [],
      d;
    a = a.replace(/\s|0x/g, '');
    d = a.length;
    a += '00000000';
    for (b = 0; b < a.length; b += 8) c.push(parseInt(a.substr(b, 8), 16) ^ 0);
    return sjcl.bitArray.clamp(c, 4 * d);
  },
};
sjcl.codec.base64 = {
  V: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  fromBits: function (a, b, c) {
    var d = '',
      e = 0,
      f = sjcl.codec.base64.V,
      g = 0,
      h = sjcl.bitArray.bitLength(a);
    c && (f = f.substr(0, 62) + '-_');
    for (c = 0; 6 * d.length < h; )
      (d += f.charAt((g ^ (a[c] >>> e)) >>> 26)),
        6 > e ? ((g = a[c] << (6 - e)), (e += 26), c++) : ((g <<= 6), (e -= 6));
    for (; d.length & 3 && !b; ) d += '=';
    return d;
  },
  toBits: function (a, b) {
    a = a.replace(/\s|=/g, '');
    var c = [],
      d,
      e = 0,
      f = sjcl.codec.base64.V,
      g = 0,
      h;
    b && (f = f.substr(0, 62) + '-_');
    for (d = 0; d < a.length; d++)
      (h = f.indexOf(a.charAt(d))),
        0 > h && q(new sjcl.exception.invalid("this isn't base64!")),
        26 < e ? ((e -= 26), c.push(g ^ (h >>> e)), (g = h << (32 - e))) : ((e += 6), (g ^= h << (32 - e)));
    e & 56 && c.push(sjcl.bitArray.partial(e & 56, g, 1));
    return c;
  },
};
sjcl.codec.base64url = {
  fromBits: function (a) {
    return sjcl.codec.base64.fromBits(a, 1, 1);
  },
  toBits: function (a) {
    return sjcl.codec.base64.toBits(a, 1);
  },
};
sjcl.codec.bytes = {
  fromBits: function (a) {
    var b = [],
      c = sjcl.bitArray.bitLength(a),
      d,
      e;
    for (d = 0; d < c / 8; d++) 0 === (d & 3) && (e = a[d / 4]), b.push(e >>> 24), (e <<= 8);
    return b;
  },
  toBits: function (a) {
    var b = [],
      c,
      d = 0;
    for (c = 0; c < a.length; c++) (d = (d << 8) | a[c]), 3 === (c & 3) && (b.push(d), (d = 0));
    c & 3 && b.push(sjcl.bitArray.partial(8 * (c & 3), d));
    return b;
  },
};
sjcl.hash.sha256 = function (a) {
  this.d[0] || this.Q();
  a ? ((this.h = a.h.slice(0)), (this.f = a.f.slice(0)), (this.e = a.e)) : this.reset();
};
sjcl.hash.sha256.hash = function (a) {
  return new sjcl.hash.sha256().update(a).finalize();
};
sjcl.hash.sha256.prototype = {
  blockSize: 512,
  reset: function () {
    this.h = this.H.slice(0);
    this.f = [];
    this.e = 0;
    return this;
  },
  update: function (a) {
    'string' === typeof a && (a = sjcl.codec.utf8String.toBits(a));
    var b,
      c = (this.f = sjcl.bitArray.concat(this.f, a));
    b = this.e;
    a = this.e = b + sjcl.bitArray.bitLength(a);
    for (b = (512 + b) & -512; b <= a; b += 512) this.A(c.splice(0, 16));
    return this;
  },
  finalize: function () {
    var a,
      b = this.f,
      c = this.h,
      b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (a = b.length + 2; a & 15; a++) b.push(0);
    b.push(Math.floor(this.e / 4294967296));
    for (b.push(this.e | 0); b.length; ) this.A(b.splice(0, 16));
    this.reset();
    return c;
  },
  H: [],
  d: [],
  Q: function () {
    function a(a) {
      return (0x100000000 * (a - Math.floor(a))) | 0;
    }
    var b = 0,
      c = 2,
      d;
    a: for (; 64 > b; c++) {
      for (d = 2; d * d <= c; d++) if (0 === c % d) continue a;
      8 > b && (this.H[b] = a(Math.pow(c, 0.5)));
      this.d[b] = a(Math.pow(c, 1 / 3));
      b++;
    }
  },
  A: function (a) {
    var b,
      c,
      d = a.slice(0),
      e = this.h,
      f = this.d,
      g = e[0],
      h = e[1],
      k = e[2],
      l = e[3],
      n = e[4],
      m = e[5],
      p = e[6],
      s = e[7];
    for (a = 0; 64 > a; a++)
      16 > a
        ? (b = d[a])
        : ((b = d[(a + 1) & 15]),
          (c = d[(a + 14) & 15]),
          (b = d[a & 15] =
            (((b >>> 7) ^ (b >>> 18) ^ (b >>> 3) ^ (b << 25) ^ (b << 14)) +
              ((c >>> 17) ^ (c >>> 19) ^ (c >>> 10) ^ (c << 15) ^ (c << 13)) +
              d[a & 15] +
              d[(a + 9) & 15]) |
            0)),
        (b =
          b +
          s +
          ((n >>> 6) ^ (n >>> 11) ^ (n >>> 25) ^ (n << 26) ^ (n << 21) ^ (n << 7)) +
          (p ^ (n & (m ^ p))) +
          f[a]),
        (s = p),
        (p = m),
        (m = n),
        (n = (l + b) | 0),
        (l = k),
        (k = h),
        (h = g),
        (g =
          (b + ((h & k) ^ (l & (h ^ k))) + ((h >>> 2) ^ (h >>> 13) ^ (h >>> 22) ^ (h << 30) ^ (h << 19) ^ (h << 10))) |
          0);
    e[0] = (e[0] + g) | 0;
    e[1] = (e[1] + h) | 0;
    e[2] = (e[2] + k) | 0;
    e[3] = (e[3] + l) | 0;
    e[4] = (e[4] + n) | 0;
    e[5] = (e[5] + m) | 0;
    e[6] = (e[6] + p) | 0;
    e[7] = (e[7] + s) | 0;
  },
};
sjcl.hash.sha1 = function (a) {
  a ? ((this.h = a.h.slice(0)), (this.f = a.f.slice(0)), (this.e = a.e)) : this.reset();
};
sjcl.hash.sha1.hash = function (a) {
  return new sjcl.hash.sha1().update(a).finalize();
};
sjcl.hash.sha1.prototype = {
  blockSize: 512,
  reset: function () {
    this.h = this.H.slice(0);
    this.f = [];
    this.e = 0;
    return this;
  },
  update: function (a) {
    'string' === typeof a && (a = sjcl.codec.utf8String.toBits(a));
    var b,
      c = (this.f = sjcl.bitArray.concat(this.f, a));
    b = this.e;
    a = this.e = b + sjcl.bitArray.bitLength(a);
    for (b = (this.blockSize + b) & -this.blockSize; b <= a; b += this.blockSize) this.A(c.splice(0, 16));
    return this;
  },
  finalize: function () {
    var a,
      b = this.f,
      c = this.h,
      b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (a = b.length + 2; a & 15; a++) b.push(0);
    b.push(Math.floor(this.e / 0x100000000));
    for (b.push(this.e | 0); b.length; ) this.A(b.splice(0, 16));
    this.reset();
    return c;
  },
  H: [1732584193, 4023233417, 2562383102, 271733878, 3285377520],
  d: [1518500249, 1859775393, 2400959708, 3395469782],
  A: function (a) {
    var b,
      c,
      d,
      e,
      f,
      g,
      h = a.slice(0),
      k = this.h;
    c = k[0];
    d = k[1];
    e = k[2];
    f = k[3];
    g = k[4];
    for (a = 0; 79 >= a; a++)
      16 <= a &&
        (h[a] =
          ((h[a - 3] ^ h[a - 8] ^ h[a - 14] ^ h[a - 16]) << 1) |
          ((h[a - 3] ^ h[a - 8] ^ h[a - 14] ^ h[a - 16]) >>> 31)),
        (b =
          19 >= a
            ? (d & e) | (~d & f)
            : 39 >= a
            ? d ^ e ^ f
            : 59 >= a
            ? (d & e) | (d & f) | (e & f)
            : 79 >= a
            ? d ^ e ^ f
            : t),
        (b = (((c << 5) | (c >>> 27)) + b + g + h[a] + this.d[Math.floor(a / 20)]) | 0),
        (g = f),
        (f = e),
        (e = (d << 30) | (d >>> 2)),
        (d = c),
        (c = b);
    k[0] = (k[0] + c) | 0;
    k[1] = (k[1] + d) | 0;
    k[2] = (k[2] + e) | 0;
    k[3] = (k[3] + f) | 0;
    k[4] = (k[4] + g) | 0;
  },
};
sjcl.mode.ccm = {
  name: 'ccm',
  I: [],
  listenProgress: function (a) {
    sjcl.mode.ccm.I.push(a);
  },
  unListenProgress: function (a) {
    a = sjcl.mode.ccm.I.indexOf(a);
    -1 < a && sjcl.mode.ccm.I.splice(a, 1);
  },
  ha: function (a) {
    var b = sjcl.mode.ccm.I.slice(),
      c;
    for (c = 0; c < b.length; c += 1) b[c](a);
  },
  encrypt: function (a, b, c, d, e) {
    var f,
      g = b.slice(0),
      h = sjcl.bitArray,
      k = h.bitLength(c) / 8,
      l = h.bitLength(g) / 8;
    e = e || 64;
    d = d || [];
    7 > k && q(new sjcl.exception.invalid('ccm: iv must be at least 7 bytes'));
    for (f = 2; 4 > f && l >>> (8 * f); f++);
    f < 15 - k && (f = 15 - k);
    c = h.clamp(c, 8 * (15 - f));
    b = sjcl.mode.ccm.X(a, b, c, d, e, f);
    g = sjcl.mode.ccm.B(a, g, c, b, e, f);
    return h.concat(g.data, g.tag);
  },
  decrypt: function (a, b, c, d, e) {
    e = e || 64;
    d = d || [];
    var f = sjcl.bitArray,
      g = f.bitLength(c) / 8,
      h = f.bitLength(b),
      k = f.clamp(b, h - e),
      l = f.bitSlice(b, h - e),
      h = (h - e) / 8;
    7 > g && q(new sjcl.exception.invalid('ccm: iv must be at least 7 bytes'));
    for (b = 2; 4 > b && h >>> (8 * b); b++);
    b < 15 - g && (b = 15 - g);
    c = f.clamp(c, 8 * (15 - b));
    k = sjcl.mode.ccm.B(a, k, c, l, e, b);
    a = sjcl.mode.ccm.X(a, k.data, c, d, e, b);
    f.equal(k.tag, a) || q(new sjcl.exception.corrupt("ccm: tag doesn't match"));
    return k.data;
  },
  pa: function (a, b, c, d, e, f) {
    var g = [],
      h = sjcl.bitArray,
      k = h.n;
    d = [h.partial(8, (b.length ? 64 : 0) | ((d - 2) << 2) | (f - 1))];
    d = h.concat(d, c);
    d[3] |= e;
    d = a.encrypt(d);
    if (b.length) {
      c = h.bitLength(b) / 8;
      65279 >= c ? (g = [h.partial(16, c)]) : 0xffffffff >= c && (g = h.concat([h.partial(16, 65534)], [c]));
      g = h.concat(g, b);
      for (b = 0; b < g.length; b += 4) d = a.encrypt(k(d, g.slice(b, b + 4).concat([0, 0, 0])));
    }
    return d;
  },
  X: function (a, b, c, d, e, f) {
    var g = sjcl.bitArray,
      h = g.n;
    e /= 8;
    (e % 2 || 4 > e || 16 < e) && q(new sjcl.exception.invalid('ccm: invalid tag length'));
    (0xffffffff < d.length || 0xffffffff < b.length) &&
      q(new sjcl.exception.bug("ccm: can't deal with 4GiB or more data"));
    c = sjcl.mode.ccm.pa(a, d, c, e, g.bitLength(b) / 8, f);
    for (d = 0; d < b.length; d += 4) c = a.encrypt(h(c, b.slice(d, d + 4).concat([0, 0, 0])));
    return g.clamp(c, 8 * e);
  },
  B: function (a, b, c, d, e, f) {
    var g,
      h = sjcl.bitArray;
    g = h.n;
    var k = b.length,
      l = h.bitLength(b),
      n = k / 50,
      m = n;
    c = h
      .concat([h.partial(8, f - 1)], c)
      .concat([0, 0, 0])
      .slice(0, 4);
    d = h.bitSlice(g(d, a.encrypt(c)), 0, e);
    if (!k) return { tag: d, data: [] };
    for (g = 0; g < k; g += 4)
      g > n && (sjcl.mode.ccm.ha(g / k), (n += m)),
        c[3]++,
        (e = a.encrypt(c)),
        (b[g] ^= e[0]),
        (b[g + 1] ^= e[1]),
        (b[g + 2] ^= e[2]),
        (b[g + 3] ^= e[3]);
    return { tag: d, data: h.clamp(b, l) };
  },
};
sjcl.mode.ocb2 = {
  name: 'ocb2',
  encrypt: function (a, b, c, d, e, f) {
    128 !== sjcl.bitArray.bitLength(c) && q(new sjcl.exception.invalid('ocb iv must be 128 bits'));
    var g,
      h = sjcl.mode.ocb2.T,
      k = sjcl.bitArray,
      l = k.n,
      n = [0, 0, 0, 0];
    c = h(a.encrypt(c));
    var m,
      p = [];
    d = d || [];
    e = e || 64;
    for (g = 0; g + 4 < b.length; g += 4)
      (m = b.slice(g, g + 4)), (n = l(n, m)), (p = p.concat(l(c, a.encrypt(l(c, m))))), (c = h(c));
    m = b.slice(g);
    b = k.bitLength(m);
    g = a.encrypt(l(c, [0, 0, 0, b]));
    m = k.clamp(l(m.concat([0, 0, 0]), g), b);
    n = l(n, l(m.concat([0, 0, 0]), g));
    n = a.encrypt(l(n, l(c, h(c))));
    d.length && (n = l(n, f ? d : sjcl.mode.ocb2.pmac(a, d)));
    return p.concat(k.concat(m, k.clamp(n, e)));
  },
  decrypt: function (a, b, c, d, e, f) {
    128 !== sjcl.bitArray.bitLength(c) && q(new sjcl.exception.invalid('ocb iv must be 128 bits'));
    e = e || 64;
    var g = sjcl.mode.ocb2.T,
      h = sjcl.bitArray,
      k = h.n,
      l = [0, 0, 0, 0],
      n = g(a.encrypt(c)),
      m,
      p,
      s = sjcl.bitArray.bitLength(b) - e,
      r = [];
    d = d || [];
    for (c = 0; c + 4 < s / 32; c += 4)
      (m = k(n, a.decrypt(k(n, b.slice(c, c + 4))))), (l = k(l, m)), (r = r.concat(m)), (n = g(n));
    p = s - 32 * c;
    m = a.encrypt(k(n, [0, 0, 0, p]));
    m = k(m, h.clamp(b.slice(c), p).concat([0, 0, 0]));
    l = k(l, m);
    l = a.encrypt(k(l, k(n, g(n))));
    d.length && (l = k(l, f ? d : sjcl.mode.ocb2.pmac(a, d)));
    h.equal(h.clamp(l, e), h.bitSlice(b, s)) || q(new sjcl.exception.corrupt("ocb: tag doesn't match"));
    return r.concat(h.clamp(m, p));
  },
  pmac: function (a, b) {
    var c,
      d = sjcl.mode.ocb2.T,
      e = sjcl.bitArray,
      f = e.n,
      g = [0, 0, 0, 0],
      h = a.encrypt([0, 0, 0, 0]),
      h = f(h, d(d(h)));
    for (c = 0; c + 4 < b.length; c += 4) (h = d(h)), (g = f(g, a.encrypt(f(h, b.slice(c, c + 4)))));
    c = b.slice(c);
    128 > e.bitLength(c) && ((h = f(h, d(h))), (c = e.concat(c, [-2147483648, 0, 0, 0])));
    g = f(g, c);
    return a.encrypt(f(d(f(h, d(h))), g));
  },
  T: function (a) {
    return [
      (a[0] << 1) ^ (a[1] >>> 31),
      (a[1] << 1) ^ (a[2] >>> 31),
      (a[2] << 1) ^ (a[3] >>> 31),
      (a[3] << 1) ^ (135 * (a[0] >>> 31)),
    ];
  },
};
sjcl.mode.gcm = {
  name: 'gcm',
  encrypt: function (a, b, c, d, e) {
    var f = b.slice(0);
    b = sjcl.bitArray;
    d = d || [];
    a = sjcl.mode.gcm.B(u, a, f, d, c, e || 128);
    return b.concat(a.data, a.tag);
  },
  decrypt: function (a, b, c, d, e) {
    var f = b.slice(0),
      g = sjcl.bitArray,
      h = g.bitLength(f);
    e = e || 128;
    d = d || [];
    e <= h ? ((b = g.bitSlice(f, h - e)), (f = g.bitSlice(f, 0, h - e))) : ((b = f), (f = []));
    a = sjcl.mode.gcm.B(v, a, f, d, c, e);
    g.equal(a.tag, b) || q(new sjcl.exception.corrupt("gcm: tag doesn't match"));
    return a.data;
  },
  ma: function (a, b) {
    var c,
      d,
      e,
      f,
      g,
      h = sjcl.bitArray.n;
    e = [0, 0, 0, 0];
    f = b.slice(0);
    for (c = 0; 128 > c; c++) {
      (d = 0 !== (a[Math.floor(c / 32)] & (1 << (31 - (c % 32))))) && (e = h(e, f));
      g = 0 !== (f[3] & 1);
      for (d = 3; 0 < d; d--) f[d] = (f[d] >>> 1) | ((f[d - 1] & 1) << 31);
      f[0] >>>= 1;
      g && (f[0] ^= -0x1f000000);
    }
    return e;
  },
  p: function (a, b, c) {
    var d,
      e = c.length;
    b = b.slice(0);
    for (d = 0; d < e; d += 4)
      (b[0] ^= 0xffffffff & c[d]),
        (b[1] ^= 0xffffffff & c[d + 1]),
        (b[2] ^= 0xffffffff & c[d + 2]),
        (b[3] ^= 0xffffffff & c[d + 3]),
        (b = sjcl.mode.gcm.ma(b, a));
    return b;
  },
  B: function (a, b, c, d, e, f) {
    var g,
      h,
      k,
      l,
      n,
      m,
      p,
      s,
      r = sjcl.bitArray;
    m = c.length;
    p = r.bitLength(c);
    s = r.bitLength(d);
    h = r.bitLength(e);
    g = b.encrypt([0, 0, 0, 0]);
    96 === h
      ? ((e = e.slice(0)), (e = r.concat(e, [1])))
      : ((e = sjcl.mode.gcm.p(g, [0, 0, 0, 0], e)),
        (e = sjcl.mode.gcm.p(g, e, [0, 0, Math.floor(h / 0x100000000), h & 0xffffffff])));
    h = sjcl.mode.gcm.p(g, [0, 0, 0, 0], d);
    n = e.slice(0);
    d = h.slice(0);
    a || (d = sjcl.mode.gcm.p(g, h, c));
    for (l = 0; l < m; l += 4)
      n[3]++, (k = b.encrypt(n)), (c[l] ^= k[0]), (c[l + 1] ^= k[1]), (c[l + 2] ^= k[2]), (c[l + 3] ^= k[3]);
    c = r.clamp(c, p);
    a && (d = sjcl.mode.gcm.p(g, h, c));
    a = [Math.floor(s / 0x100000000), s & 0xffffffff, Math.floor(p / 0x100000000), p & 0xffffffff];
    d = sjcl.mode.gcm.p(g, d, a);
    k = b.encrypt(e);
    d[0] ^= k[0];
    d[1] ^= k[1];
    d[2] ^= k[2];
    d[3] ^= k[3];
    return { tag: r.bitSlice(d, 0, f), data: c };
  },
};
sjcl.misc.hmac = function (a, b) {
  this.Y = b = b || sjcl.hash.sha256;
  var c = [[], []],
    d,
    e = b.prototype.blockSize / 32;
  this.w = [new b(), new b()];
  a.length > e && (a = b.hash(a));
  for (d = 0; d < e; d++) (c[0][d] = a[d] ^ 909522486), (c[1][d] = a[d] ^ 1549556828);
  this.w[0].update(c[0]);
  this.w[1].update(c[1]);
  this.S = new b(this.w[0]);
};
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (a) {
  this.ca && q(new sjcl.exception.invalid('encrypt on already updated hmac called!'));
  this.update(a);
  return this.digest(a);
};
sjcl.misc.hmac.prototype.reset = function () {
  this.S = new this.Y(this.w[0]);
  this.ca = v;
};
sjcl.misc.hmac.prototype.update = function (a) {
  this.ca = u;
  this.S.update(a);
};
sjcl.misc.hmac.prototype.digest = function () {
  var a = this.S.finalize(),
    a = new this.Y(this.w[1]).update(a).finalize();
  this.reset();
  return a;
};
sjcl.misc.pbkdf2 = function (a, b, c, d, e) {
  c = c || 1e3;
  (0 > d || 0 > c) && q(sjcl.exception.invalid('invalid params to pbkdf2'));
  'string' === typeof a && (a = sjcl.codec.utf8String.toBits(a));
  'string' === typeof b && (b = sjcl.codec.utf8String.toBits(b));
  e = e || sjcl.misc.hmac;
  a = new e(a);
  var f,
    g,
    h,
    k,
    l = [],
    n = sjcl.bitArray;
  for (k = 1; 32 * l.length < (d || 1); k++) {
    e = f = a.encrypt(n.concat(b, [k]));
    for (g = 1; g < c; g++) {
      f = a.encrypt(f);
      for (h = 0; h < f.length; h++) e[h] ^= f[h];
    }
    l = l.concat(e);
  }
  d && (l = n.clamp(l, d));
  return l;
};
sjcl.prng = function (a) {
  this.i = [new sjcl.hash.sha256()];
  this.q = [0];
  this.R = 0;
  this.J = {};
  this.P = 0;
  this.W = {};
  this.$ = this.k = this.s = this.ja = 0;
  this.d = [0, 0, 0, 0, 0, 0, 0, 0];
  this.m = [0, 0, 0, 0];
  this.N = t;
  this.O = a;
  this.F = v;
  this.M = { progress: {}, seeded: {} };
  this.u = this.ia = 0;
  this.K = 1;
  this.L = 2;
  this.ea = 0x10000;
  this.U = [0, 48, 64, 96, 128, 192, 0x100, 384, 512, 768, 1024];
  this.fa = 3e4;
  this.da = 80;
};
sjcl.prng.prototype = {
  randomWords: function (a, b) {
    var c = [],
      d;
    d = this.isReady(b);
    var e;
    d === this.u && q(new sjcl.exception.notReady("generator isn't seeded"));
    if (d & this.L) {
      d = !(d & this.K);
      e = [];
      var f = 0,
        g;
      this.$ = e[0] = new Date().valueOf() + this.fa;
      for (g = 0; 16 > g; g++) e.push((0x100000000 * Math.random()) | 0);
      for (
        g = 0;
        g < this.i.length &&
        !((e = e.concat(this.i[g].finalize())), (f += this.q[g]), (this.q[g] = 0), !d && this.R & (1 << g));
        g++
      );
      this.R >= 1 << this.i.length && (this.i.push(new sjcl.hash.sha256()), this.q.push(0));
      this.k -= f;
      f > this.s && (this.s = f);
      this.R++;
      this.d = sjcl.hash.sha256.hash(this.d.concat(e));
      this.N = new sjcl.cipher.aes(this.d);
      for (d = 0; 4 > d && !((this.m[d] = (this.m[d] + 1) | 0), this.m[d]); d++);
    }
    for (d = 0; d < a; d += 4) 0 === (d + 1) % this.ea && x(this), (e = y(this)), c.push(e[0], e[1], e[2], e[3]);
    x(this);
    return c.slice(0, a);
  },
  setDefaultParanoia: function (a, b) {
    0 === a &&
      'Setting paranoia=0 will ruin your security; use it only for testing' !== b &&
      q('Setting paranoia=0 will ruin your security; use it only for testing');
    this.O = a;
  },
  addEntropy: function (a, b, c) {
    c = c || 'user';
    var d,
      e,
      f = new Date().valueOf(),
      g = this.J[c],
      h = this.isReady(),
      k = 0;
    d = this.W[c];
    d === t && (d = this.W[c] = this.ja++);
    g === t && (g = this.J[c] = 0);
    this.J[c] = (this.J[c] + 1) % this.i.length;
    switch (typeof a) {
      case 'number':
        b === t && (b = 1);
        this.i[g].update([d, this.P++, 1, b, f, 1, a | 0]);
        break;
      case 'object':
        c = Object.prototype.toString.call(a);
        if ('[object Uint32Array]' === c) {
          e = [];
          for (c = 0; c < a.length; c++) e.push(a[c]);
          a = e;
        } else {
          '[object Array]' !== c && (k = 1);
          for (c = 0; c < a.length && !k; c++) 'number' !== typeof a[c] && (k = 1);
        }
        if (!k) {
          if (b === t) for (c = b = 0; c < a.length; c++) for (e = a[c]; 0 < e; ) b++, (e >>>= 1);
          this.i[g].update([d, this.P++, 2, b, f, a.length].concat(a));
        }
        break;
      case 'string':
        b === t && (b = a.length);
        this.i[g].update([d, this.P++, 3, b, f, a.length]);
        this.i[g].update(a);
        break;
      default:
        k = 1;
    }
    k && q(new sjcl.exception.bug('random: addEntropy only supports number, array of numbers or string'));
    this.q[g] += b;
    this.k += b;
    h === this.u &&
      (this.isReady() !== this.u && C('seeded', Math.max(this.s, this.k)), C('progress', this.getProgress()));
  },
  isReady: function (a) {
    a = this.U[a !== t ? a : this.O];
    return this.s && this.s >= a
      ? this.q[0] > this.da && new Date().valueOf() > this.$
        ? this.L | this.K
        : this.K
      : this.k >= a
      ? this.L | this.u
      : this.u;
  },
  getProgress: function (a) {
    a = this.U[a ? a : this.O];
    return this.s >= a ? 1 : this.k > a ? 1 : this.k / a;
  },
  startCollectors: function () {
    this.F ||
      ((this.c = {
        loadTimeCollector: D(this, this.oa),
        mouseCollector: D(this, this.qa),
        keyboardCollector: D(this, this.na),
        accelerometerCollector: D(this, this.ga),
        touchCollector: D(this, this.sa),
      }),
      window.addEventListener
        ? (window.addEventListener('load', this.c.loadTimeCollector, v),
          window.addEventListener('mousemove', this.c.mouseCollector, v),
          window.addEventListener('keypress', this.c.keyboardCollector, v),
          window.addEventListener('devicemotion', this.c.accelerometerCollector, v),
          window.addEventListener('touchmove', this.c.touchCollector, v))
        : document.attachEvent
        ? (document.attachEvent('onload', this.c.loadTimeCollector),
          document.attachEvent('onmousemove', this.c.mouseCollector),
          document.attachEvent('keypress', this.c.keyboardCollector))
        : q(new sjcl.exception.bug("can't attach event")),
      (this.F = u));
  },
  stopCollectors: function () {
    this.F &&
      (window.removeEventListener
        ? (window.removeEventListener('load', this.c.loadTimeCollector, v),
          window.removeEventListener('mousemove', this.c.mouseCollector, v),
          window.removeEventListener('keypress', this.c.keyboardCollector, v),
          window.removeEventListener('devicemotion', this.c.accelerometerCollector, v),
          window.removeEventListener('touchmove', this.c.touchCollector, v))
        : document.detachEvent &&
          (document.detachEvent('onload', this.c.loadTimeCollector),
          document.detachEvent('onmousemove', this.c.mouseCollector),
          document.detachEvent('keypress', this.c.keyboardCollector)),
      (this.F = v));
  },
  addEventListener: function (a, b) {
    this.M[a][this.ia++] = b;
  },
  removeEventListener: function (a, b) {
    var c,
      d,
      e = this.M[a],
      f = [];
    for (d in e) e.hasOwnProperty(d) && e[d] === b && f.push(d);
    for (c = 0; c < f.length; c++) (d = f[c]), delete e[d];
  },
  na: function () {
    E(1);
  },
  qa: function (a) {
    var b, c;
    try {
      (b = a.x || a.clientX || a.offsetX || 0), (c = a.y || a.clientY || a.offsetY || 0);
    } catch (d) {
      c = b = 0;
    }
    0 != b && 0 != c && sjcl.random.addEntropy([b, c], 2, 'mouse');
    E(0);
  },
  sa: function (a) {
    a = a.touches[0] || a.changedTouches[0];
    sjcl.random.addEntropy([a.pageX || a.clientX, a.pageY || a.clientY], 1, 'touch');
    E(0);
  },
  oa: function () {
    E(2);
  },
  ga: function (a) {
    a = a.accelerationIncludingGravity.x || a.accelerationIncludingGravity.y || a.accelerationIncludingGravity.z;
    if (window.orientation) {
      var b = window.orientation;
      'number' === typeof b && sjcl.random.addEntropy(b, 1, 'accelerometer');
    }
    a && sjcl.random.addEntropy(a, 2, 'accelerometer');
    E(0);
  },
};
function C(a, b) {
  var c,
    d = sjcl.random.M[a],
    e = [];
  for (c in d) d.hasOwnProperty(c) && e.push(d[c]);
  for (c = 0; c < e.length; c++) e[c](b);
}
function E(a) {
  'undefined' !== typeof window && window.performance && 'function' === typeof window.performance.now
    ? sjcl.random.addEntropy(window.performance.now(), a, 'loadtime')
    : sjcl.random.addEntropy(new Date().valueOf(), a, 'loadtime');
}
function x(a) {
  a.d = y(a).concat(y(a));
  a.N = new sjcl.cipher.aes(a.d);
}
function y(a) {
  for (var b = 0; 4 > b && !((a.m[b] = (a.m[b] + 1) | 0), a.m[b]); b++);
  return a.N.encrypt(a.m);
}
function D(a, b) {
  return function () {
    b.apply(a, arguments);
  };
}
sjcl.random = new sjcl.prng(6);
a: try {
  var F, G, H, I;
  if ((I = 'undefined' !== typeof module)) {
    var J;
    if ((J = module.exports)) {
      var K;
      try {
        K = require('crypto');
      } catch (L) {
        K = null;
      }
      J = (G = K) && G.randomBytes;
    }
    I = J;
  }
  if (I)
    (F = G.randomBytes(128)),
      (F = new Uint32Array(new Uint8Array(F).buffer)),
      sjcl.random.addEntropy(F, 1024, "crypto['randomBytes']");
  else if ('undefined' !== typeof window && 'undefined' !== typeof Uint32Array) {
    H = new Uint32Array(32);
    if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(H);
    else if (window.msCrypto && window.msCrypto.getRandomValues) window.msCrypto.getRandomValues(H);
    else break a;
    sjcl.random.addEntropy(H, 1024, "crypto['getRandomValues']");
  }
} catch (M) {
  'undefined' !== typeof window &&
    window.console &&
    (console.log('There was an error collecting entropy from the browser:'), console.log(M));
}
sjcl.json = {
  defaults: { v: 1, iter: 1e3, ks: 128, ts: 64, mode: 'ccm', adata: '', cipher: 'aes' },
  la: function (a, b, c, d) {
    c = c || {};
    d = d || {};
    var e = sjcl.json,
      f = e.l({ iv: sjcl.random.randomWords(4, 0) }, e.defaults),
      g;
    e.l(f, c);
    c = f.adata;
    'string' === typeof f.salt && (f.salt = sjcl.codec.base64.toBits(f.salt));
    'string' === typeof f.iv && (f.iv = sjcl.codec.base64.toBits(f.iv));
    (!sjcl.mode[f.mode] ||
      !sjcl.cipher[f.cipher] ||
      ('string' === typeof a && 100 >= f.iter) ||
      (64 !== f.ts && 96 !== f.ts && 128 !== f.ts) ||
      (128 !== f.ks && 192 !== f.ks && 0x100 !== f.ks) ||
      2 > f.iv.length ||
      4 < f.iv.length) &&
      q(new sjcl.exception.invalid('json encrypt: invalid parameters'));
    'string' === typeof a
      ? ((g = sjcl.misc.cachedPbkdf2(a, f)), (a = g.key.slice(0, f.ks / 32)), (f.salt = g.salt))
      : sjcl.ecc &&
        a instanceof sjcl.ecc.elGamal.publicKey &&
        ((g = a.kem()), (f.kemtag = g.tag), (a = g.key.slice(0, f.ks / 32)));
    'string' === typeof b && (b = sjcl.codec.utf8String.toBits(b));
    'string' === typeof c && (f.adata = c = sjcl.codec.utf8String.toBits(c));
    g = new sjcl.cipher[f.cipher](a);
    e.l(d, f);
    d.key = a;
    f.ct =
      'ccm' === f.mode && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && b instanceof ArrayBuffer
        ? sjcl.arrayBuffer.ccm.encrypt(g, b, f.iv, c, f.ts)
        : sjcl.mode[f.mode].encrypt(g, b, f.iv, c, f.ts);
    return f;
  },
  encrypt: function (a, b, c, d) {
    var e = sjcl.json,
      f = e.la.apply(e, arguments);
    return e.encode(f);
  },
  ka: function (a, b, c, d) {
    c = c || {};
    d = d || {};
    var e = sjcl.json;
    b = e.l(e.l(e.l({}, e.defaults), b), c, u);
    var f, g;
    f = b.adata;
    'string' === typeof b.salt && (b.salt = sjcl.codec.base64.toBits(b.salt));
    'string' === typeof b.iv && (b.iv = sjcl.codec.base64.toBits(b.iv));
    (!sjcl.mode[b.mode] ||
      !sjcl.cipher[b.cipher] ||
      ('string' === typeof a && 100 >= b.iter) ||
      (64 !== b.ts && 96 !== b.ts && 128 !== b.ts) ||
      (128 !== b.ks && 192 !== b.ks && 0x100 !== b.ks) ||
      !b.iv ||
      2 > b.iv.length ||
      4 < b.iv.length) &&
      q(new sjcl.exception.invalid('json decrypt: invalid parameters'));
    'string' === typeof a
      ? ((g = sjcl.misc.cachedPbkdf2(a, b)), (a = g.key.slice(0, b.ks / 32)), (b.salt = g.salt))
      : sjcl.ecc &&
        a instanceof sjcl.ecc.elGamal.secretKey &&
        (a = a.unkem(sjcl.codec.base64.toBits(b.kemtag)).slice(0, b.ks / 32));
    'string' === typeof f && (f = sjcl.codec.utf8String.toBits(f));
    g = new sjcl.cipher[b.cipher](a);
    f =
      'ccm' === b.mode && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && b.ct instanceof ArrayBuffer
        ? sjcl.arrayBuffer.ccm.decrypt(g, b.ct, b.iv, b.tag, f, b.ts)
        : sjcl.mode[b.mode].decrypt(g, b.ct, b.iv, f, b.ts);
    e.l(d, b);
    d.key = a;
    return 1 === c.raw ? f : sjcl.codec.utf8String.fromBits(f);
  },
  decrypt: function (a, b, c, d) {
    var e = sjcl.json;
    return e.ka(a, e.decode(b), c, d);
  },
  encode: function (a) {
    var b,
      c = '{',
      d = '';
    for (b in a)
      if (a.hasOwnProperty(b))
        switch (
          (b.match(/^[a-z0-9]+$/i) || q(new sjcl.exception.invalid('json encode: invalid property name')),
          (c += d + '"' + b + '":'),
          (d = ','),
          typeof a[b])
        ) {
          case 'number':
          case 'boolean':
            c += a[b];
            break;
          case 'string':
            c += '"' + escape(a[b]) + '"';
            break;
          case 'object':
            c += '"' + sjcl.codec.base64.fromBits(a[b], 0) + '"';
            break;
          default:
            q(new sjcl.exception.bug('json encode: unsupported type'));
        }
    return c + '}';
  },
  decode: function (a) {
    a = a.replace(/\s/g, '');
    a.match(/^\{.*\}$/) || q(new sjcl.exception.invalid("json decode: this isn't json!"));
    a = a.replace(/^\{|\}$/g, '').split(/,/);
    var b = {},
      c,
      d;
    for (c = 0; c < a.length; c++)
      (d = a[c].match(/^\s*(?:(["']?)([a-z][a-z0-9]*)\1)\s*:\s*(?:(-?\d+)|"([a-z0-9+\/%*_.@=\-]*)"|(true|false))$/i)) ||
        q(new sjcl.exception.invalid("json decode: this isn't json!")),
        null != d[3]
          ? (b[d[2]] = parseInt(d[3], 10))
          : null != d[4]
          ? (b[d[2]] = d[2].match(/^(ct|adata|salt|iv)$/) ? sjcl.codec.base64.toBits(d[4]) : unescape(d[4]))
          : null != d[5] && (b[d[2]] = 'true' === d[5]);
    return b;
  },
  l: function (a, b, c) {
    a === t && (a = {});
    if (b === t) return a;
    for (var d in b)
      b.hasOwnProperty(d) &&
        (c && a[d] !== t && a[d] !== b[d] && q(new sjcl.exception.invalid('required parameter overridden')),
        (a[d] = b[d]));
    return a;
  },
  ua: function (a, b) {
    var c = {},
      d;
    for (d in a) a.hasOwnProperty(d) && a[d] !== b[d] && (c[d] = a[d]);
    return c;
  },
  ta: function (a, b) {
    var c = {},
      d;
    for (d = 0; d < b.length; d++) a[b[d]] !== t && (c[b[d]] = a[b[d]]);
    return c;
  },
};
sjcl.encrypt = sjcl.json.encrypt;
sjcl.decrypt = sjcl.json.decrypt;
sjcl.misc.ra = {};
sjcl.misc.cachedPbkdf2 = function (a, b) {
  var c = sjcl.misc.ra,
    d;
  b = b || {};
  d = b.iter || 1e3;
  c = c[a] = c[a] || {};
  d = c[d] = c[d] || { firstSalt: b.salt && b.salt.length ? b.salt.slice(0) : sjcl.random.randomWords(2, 0) };
  c = b.salt === t ? d.firstSalt : b.salt;
  d[c] = d[c] || sjcl.misc.pbkdf2(a, c, b.iter);
  return { key: d[c].slice(0), salt: c.slice(0) };
};
sjcl.bn = function (a) {
  this.initWith(a);
};
sjcl.bn.prototype = {
  radix: 24,
  maxMul: 8,
  g: sjcl.bn,
  copy: function () {
    return new this.g(this);
  },
  initWith: function (a) {
    var b = 0,
      c;
    switch (typeof a) {
      case 'object':
        this.limbs = a.limbs.slice(0);
        break;
      case 'number':
        this.limbs = [a];
        this.normalize();
        break;
      case 'string':
        a = a.replace(/^0x/, '');
        this.limbs = [];
        c = this.radix / 4;
        for (b = 0; b < a.length; b += c)
          this.limbs.push(parseInt(a.substring(Math.max(a.length - b - c, 0), a.length - b), 16));
        break;
      default:
        this.limbs = [0];
    }
    return this;
  },
  equals: function (a) {
    'number' === typeof a && (a = new this.g(a));
    var b = 0,
      c;
    this.fullReduce();
    a.fullReduce();
    for (c = 0; c < this.limbs.length || c < a.limbs.length; c++) b |= this.getLimb(c) ^ a.getLimb(c);
    return 0 === b;
  },
  getLimb: function (a) {
    return a >= this.limbs.length ? 0 : this.limbs[a];
  },
  greaterEquals: function (a) {
    'number' === typeof a && (a = new this.g(a));
    var b = 0,
      c = 0,
      d,
      e,
      f;
    for (d = Math.max(this.limbs.length, a.limbs.length) - 1; 0 <= d; d--)
      (e = this.getLimb(d)), (f = a.getLimb(d)), (c |= (f - e) & ~b), (b |= (e - f) & ~c);
    return (c | ~b) >>> 31;
  },
  toString: function () {
    this.fullReduce();
    var a = '',
      b,
      c,
      d = this.limbs;
    for (b = 0; b < this.limbs.length; b++) {
      for (c = d[b].toString(16); b < this.limbs.length - 1 && 6 > c.length; ) c = '0' + c;
      a = c + a;
    }
    return '0x' + a;
  },
  addM: function (a) {
    'object' !== typeof a && (a = new this.g(a));
    var b = this.limbs,
      c = a.limbs;
    for (a = b.length; a < c.length; a++) b[a] = 0;
    for (a = 0; a < c.length; a++) b[a] += c[a];
    return this;
  },
  doubleM: function () {
    var a,
      b = 0,
      c,
      d = this.radix,
      e = this.radixMask,
      f = this.limbs;
    for (a = 0; a < f.length; a++) (c = f[a]), (c = c + c + b), (f[a] = c & e), (b = c >> d);
    b && f.push(b);
    return this;
  },
  halveM: function () {
    var a,
      b = 0,
      c,
      d = this.radix,
      e = this.limbs;
    for (a = e.length - 1; 0 <= a; a--) (c = e[a]), (e[a] = (c + b) >> 1), (b = (c & 1) << d);
    e[e.length - 1] || e.pop();
    return this;
  },
  subM: function (a) {
    'object' !== typeof a && (a = new this.g(a));
    var b = this.limbs,
      c = a.limbs;
    for (a = b.length; a < c.length; a++) b[a] = 0;
    for (a = 0; a < c.length; a++) b[a] -= c[a];
    return this;
  },
  mod: function (a) {
    var b = !this.greaterEquals(new sjcl.bn(0));
    a = new sjcl.bn(a).normalize();
    var c = new sjcl.bn(this).normalize(),
      d = 0;
    for (b && (c = new sjcl.bn(0).subM(c).normalize()); c.greaterEquals(a); d++) a.doubleM();
    for (b && (c = a.sub(c).normalize()); 0 < d; d--) a.halveM(), c.greaterEquals(a) && c.subM(a).normalize();
    return c.trim();
  },
  inverseMod: function (a) {
    var b = new sjcl.bn(1),
      c = new sjcl.bn(0),
      d = new sjcl.bn(this),
      e = new sjcl.bn(a),
      f,
      g = 1;
    a.limbs[0] & 1 || q(new sjcl.exception.invalid('inverseMod: p must be odd'));
    do {
      d.limbs[0] & 1 &&
        (d.greaterEquals(e) || ((f = d), (d = e), (e = f), (f = b), (b = c), (c = f)),
        d.subM(e),
        d.normalize(),
        b.greaterEquals(c) || b.addM(a),
        b.subM(c));
      d.halveM();
      b.limbs[0] & 1 && b.addM(a);
      b.normalize();
      b.halveM();
      for (f = g = 0; f < d.limbs.length; f++) g |= d.limbs[f];
    } while (g);
    e.equals(1) || q(new sjcl.exception.invalid('inverseMod: p and x must be relatively prime'));
    return c;
  },
  add: function (a) {
    return this.copy().addM(a);
  },
  sub: function (a) {
    return this.copy().subM(a);
  },
  mul: function (a) {
    'number' === typeof a && (a = new this.g(a));
    var b,
      c = this.limbs,
      d = a.limbs,
      e = c.length,
      f = d.length,
      g = new this.g(),
      h = g.limbs,
      k,
      l = this.maxMul;
    for (b = 0; b < this.limbs.length + a.limbs.length + 1; b++) h[b] = 0;
    for (b = 0; b < e; b++) {
      k = c[b];
      for (a = 0; a < f; a++) h[b + a] += k * d[a];
      --l || ((l = this.maxMul), g.cnormalize());
    }
    return g.cnormalize().reduce();
  },
  square: function () {
    return this.mul(this);
  },
  power: function (a) {
    a = new sjcl.bn(a).normalize().trim().limbs;
    var b,
      c,
      d = new this.g(1),
      e = this;
    for (b = 0; b < a.length; b++)
      for (c = 0; c < this.radix; c++) {
        a[b] & (1 << c) && (d = d.mul(e));
        if (b == a.length - 1 && 0 == a[b] >> (c + 1)) break;
        e = e.square();
      }
    return d;
  },
  mulmod: function (a, b) {
    return this.mod(b).mul(a.mod(b)).mod(b);
  },
  powermod: function (a, b) {
    a = new sjcl.bn(a);
    b = new sjcl.bn(b);
    if (1 == (b.limbs[0] & 1)) {
      var c = this.montpowermod(a, b);
      if (c != v) return c;
    }
    for (var d, e = a.normalize().trim().limbs, f = new this.g(1), g = this, c = 0; c < e.length; c++)
      for (d = 0; d < this.radix; d++) {
        e[c] & (1 << d) && (f = f.mulmod(g, b));
        if (c == e.length - 1 && 0 == e[c] >> (d + 1)) break;
        g = g.mulmod(g, b);
      }
    return f;
  },
  montpowermod: function (a, b) {
    function c(a, b) {
      var c = b % a.radix;
      return (a.limbs[Math.floor(b / a.radix)] & (1 << c)) >> c;
    }
    function d(a, c) {
      var d,
        e,
        f = (1 << (l + 1)) - 1;
      d = a.mul(c);
      e = d.mul(s);
      e.limbs = e.limbs.slice(0, k.limbs.length);
      e.limbs.length == k.limbs.length && (e.limbs[k.limbs.length - 1] &= f);
      e = e.mul(b);
      e = d.add(e).normalize().trim();
      e.limbs = e.limbs.slice(k.limbs.length - 1);
      for (d = 0; d < e.limbs.length; d++)
        0 < d && (e.limbs[d - 1] |= (e.limbs[d] & f) << (g - l - 1)), (e.limbs[d] >>= l + 1);
      e.greaterEquals(b) && e.subM(b);
      return e;
    }
    a = new sjcl.bn(a).normalize().trim();
    b = new sjcl.bn(b);
    var e,
      f,
      g = this.radix,
      h = new this.g(1);
    e = this.copy();
    var k, l, n;
    n = a.bitLength();
    k = new sjcl.bn({
      limbs: b
        .copy()
        .normalize()
        .trim()
        .limbs.map(function () {
          return 0;
        }),
    });
    for (l = this.radix; 0 < l; l--)
      if (1 == ((b.limbs[b.limbs.length - 1] >> l) & 1)) {
        k.limbs[k.limbs.length - 1] = 1 << l;
        break;
      }
    if (0 == n) return this;
    n = 18 > n ? 1 : 48 > n ? 3 : 144 > n ? 4 : 768 > n ? 5 : 6;
    var m = k.copy(),
      p = b.copy();
    f = new sjcl.bn(1);
    for (var s = new sjcl.bn(0), r = k.copy(); r.greaterEquals(1); )
      r.halveM(), 0 == (f.limbs[0] & 1) ? (f.halveM(), s.halveM()) : (f.addM(p), f.halveM(), s.halveM(), s.addM(m));
    f = f.normalize();
    s = s.normalize();
    m.doubleM();
    p = m.mulmod(m, b);
    if (!m.mul(f).sub(b.mul(s)).equals(1)) return v;
    e = d(e, p);
    h = d(h, p);
    m = {};
    f = (1 << (n - 1)) - 1;
    m[1] = e.copy();
    m[2] = d(e, e);
    for (e = 1; e <= f; e++) m[2 * e + 1] = d(m[2 * e - 1], m[2]);
    for (e = a.bitLength() - 1; 0 <= e; )
      if (0 == c(a, e)) (h = d(h, h)), (e -= 1);
      else {
        for (p = e - n + 1; 0 == c(a, p); ) p++;
        r = 0;
        for (f = p; f <= e; f++) (r += c(a, f) << (f - p)), (h = d(h, h));
        h = d(h, m[r]);
        e = p - 1;
      }
    return d(h, 1);
  },
  trim: function () {
    var a = this.limbs,
      b;
    do b = a.pop();
    while (a.length && 0 === b);
    a.push(b);
    return this;
  },
  reduce: function () {
    return this;
  },
  fullReduce: function () {
    return this.normalize();
  },
  normalize: function () {
    var a = 0,
      b,
      c = this.placeVal,
      d = this.ipv,
      e,
      f = this.limbs,
      g = f.length,
      h = this.radixMask;
    for (b = 0; b < g || (0 !== a && -1 !== a); b++) (a = (f[b] || 0) + a), (e = f[b] = a & h), (a = (a - e) * d);
    -1 === a && (f[b - 1] -= c);
    return this;
  },
  cnormalize: function () {
    var a = 0,
      b,
      c = this.ipv,
      d,
      e = this.limbs,
      f = e.length,
      g = this.radixMask;
    for (b = 0; b < f - 1; b++) (a = e[b] + a), (d = e[b] = a & g), (a = (a - d) * c);
    e[b] += a;
    return this;
  },
  toBits: function (a) {
    this.fullReduce();
    a = a || this.exponent || this.bitLength();
    var b = Math.floor((a - 1) / 24),
      c = sjcl.bitArray,
      d = [c.partial(((a + 7) & -8) % this.radix || this.radix, this.getLimb(b))];
    for (b--; 0 <= b; b--) (d = c.concat(d, [c.partial(Math.min(this.radix, a), this.getLimb(b))])), (a -= this.radix);
    return d;
  },
  bitLength: function () {
    this.fullReduce();
    for (var a = this.radix * (this.limbs.length - 1), b = this.limbs[this.limbs.length - 1]; b; b >>>= 1) a++;
    return (a + 7) & -8;
  },
};
sjcl.bn.fromBits = function (a) {
  var b = new this(),
    c = [],
    d = sjcl.bitArray,
    e = this.prototype,
    f = Math.min(this.bitLength || 0x100000000, d.bitLength(a)),
    g = f % e.radix || e.radix;
  for (c[0] = d.extract(a, 0, g); g < f; g += e.radix) c.unshift(d.extract(a, g, e.radix));
  b.limbs = c;
  return b;
};
sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;
sjcl.bn.pseudoMersennePrime = function (a, b) {
  function c(a) {
    this.initWith(a);
  }
  var d = (c.prototype = new sjcl.bn()),
    e,
    f;
  e = d.modOffset = Math.ceil((f = a / d.radix));
  d.exponent = a;
  d.offset = [];
  d.factor = [];
  d.minOffset = e;
  d.fullMask = 0;
  d.fullOffset = [];
  d.fullFactor = [];
  d.modulus = c.modulus = new sjcl.bn(Math.pow(2, a));
  d.fullMask = 0 | -Math.pow(2, a % d.radix);
  for (e = 0; e < b.length; e++)
    (d.offset[e] = Math.floor(b[e][0] / d.radix - f)),
      (d.fullOffset[e] = Math.ceil(b[e][0] / d.radix - f)),
      (d.factor[e] = b[e][1] * Math.pow(0.5, a - b[e][0] + d.offset[e] * d.radix)),
      (d.fullFactor[e] = b[e][1] * Math.pow(0.5, a - b[e][0] + d.fullOffset[e] * d.radix)),
      d.modulus.addM(new sjcl.bn(Math.pow(2, b[e][0]) * b[e][1])),
      (d.minOffset = Math.min(d.minOffset, -d.offset[e]));
  d.g = c;
  d.modulus.cnormalize();
  d.reduce = function () {
    var a,
      b,
      c,
      d = this.modOffset,
      e = this.limbs,
      f = this.offset,
      p = this.offset.length,
      s = this.factor,
      r;
    for (a = this.minOffset; e.length > d; ) {
      c = e.pop();
      r = e.length;
      for (b = 0; b < p; b++) e[r + f[b]] -= s[b] * c;
      a--;
      a || (e.push(0), this.cnormalize(), (a = this.minOffset));
    }
    this.cnormalize();
    return this;
  };
  d.ba =
    -1 === d.fullMask
      ? d.reduce
      : function () {
          var a = this.limbs,
            b = a.length - 1,
            c,
            d;
          this.reduce();
          if (b === this.modOffset - 1) {
            d = a[b] & this.fullMask;
            a[b] -= d;
            for (c = 0; c < this.fullOffset.length; c++) a[b + this.fullOffset[c]] -= this.fullFactor[c] * d;
            this.normalize();
          }
        };
  d.fullReduce = function () {
    var a, b;
    this.ba();
    this.addM(this.modulus);
    this.addM(this.modulus);
    this.normalize();
    this.ba();
    for (b = this.limbs.length; b < this.modOffset; b++) this.limbs[b] = 0;
    a = this.greaterEquals(this.modulus);
    for (b = 0; b < this.limbs.length; b++) this.limbs[b] -= this.modulus.limbs[b] * a;
    this.cnormalize();
    return this;
  };
  d.inverse = function () {
    return this.power(this.modulus.sub(2));
  };
  c.fromBits = sjcl.bn.fromBits;
  return c;
};
var N = sjcl.bn.pseudoMersennePrime;
sjcl.bn.prime = {
  p127: N(127, [[0, -1]]),
  p25519: N(255, [[0, -19]]),
  p192k: N(192, [
    [32, -1],
    [12, -1],
    [8, -1],
    [7, -1],
    [6, -1],
    [3, -1],
    [0, -1],
  ]),
  p224k: N(224, [
    [32, -1],
    [12, -1],
    [11, -1],
    [9, -1],
    [7, -1],
    [4, -1],
    [1, -1],
    [0, -1],
  ]),
  p256k: N(0x100, [
    [32, -1],
    [9, -1],
    [8, -1],
    [7, -1],
    [6, -1],
    [4, -1],
    [0, -1],
  ]),
  p192: N(192, [
    [0, -1],
    [64, -1],
  ]),
  p224: N(224, [
    [0, 1],
    [96, -1],
  ]),
  p256: N(0x100, [
    [0, -1],
    [96, 1],
    [192, 1],
    [224, -1],
  ]),
  p384: N(384, [
    [0, -1],
    [32, 1],
    [96, -1],
    [128, -1],
  ]),
  p521: N(521, [[0, -1]]),
};
sjcl.bn.random = function (a, b) {
  'object' !== typeof a && (a = new sjcl.bn(a));
  for (var c, d, e = a.limbs.length, f = a.limbs[e - 1] + 1, g = new sjcl.bn(); ; ) {
    do (c = sjcl.random.randomWords(e, b)), 0 > c[e - 1] && (c[e - 1] += 0x100000000);
    while (Math.floor(c[e - 1] / f) === Math.floor(0x100000000 / f));
    c[e - 1] %= f;
    for (d = 0; d < e - 1; d++) c[d] &= a.radixMask;
    g.limbs = c;
    if (!g.greaterEquals(a)) return g;
  }
};
sjcl.ecc = {};
sjcl.ecc.point = function (a, b, c) {
  b === t
    ? (this.isIdentity = u)
    : (b instanceof sjcl.bn && (b = new a.field(b)),
      c instanceof sjcl.bn && (c = new a.field(c)),
      (this.x = b),
      (this.y = c),
      (this.isIdentity = v));
  this.curve = a;
};
sjcl.ecc.point.prototype = {
  toJac: function () {
    return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
  },
  mult: function (a) {
    return this.toJac().mult(a, this).toAffine();
  },
  mult2: function (a, b, c) {
    return this.toJac().mult2(a, this, b, c).toAffine();
  },
  multiples: function () {
    var a, b, c;
    if (this.Z === t) {
      c = this.toJac().doubl();
      a = this.Z = [new sjcl.ecc.point(this.curve), this, c.toAffine()];
      for (b = 3; 16 > b; b++) (c = c.add(this)), a.push(c.toAffine());
    }
    return this.Z;
  },
  negate: function () {
    var a = new this.curve.field(0).sub(this.y).normalize().reduce();
    return new sjcl.ecc.point(this.curve, this.x, a);
  },
  isValid: function () {
    return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },
  toBits: function () {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  },
};
sjcl.ecc.pointJac = function (a, b, c, d) {
  b === t ? (this.isIdentity = u) : ((this.x = b), (this.y = c), (this.z = d), (this.isIdentity = v));
  this.curve = a;
};
sjcl.ecc.pointJac.prototype = {
  add: function (a) {
    var b, c, d, e;
    this.curve !== a.curve && q("sjcl['ecc']['add'](): Points must be on the same curve to add them!");
    if (this.isIdentity) return a.toJac();
    if (a.isIdentity) return this;
    b = this.z.square();
    c = a.x.mul(b).subM(this.x);
    if (c.equals(0)) return this.y.equals(a.y.mul(b.mul(this.z))) ? this.doubl() : new sjcl.ecc.pointJac(this.curve);
    b = a.y.mul(b.mul(this.z)).subM(this.y);
    d = c.square();
    a = b.square();
    e = c.square().mul(c).addM(this.x.add(this.x).mul(d));
    a = a.subM(e);
    b = this.x.mul(d).subM(a).mul(b);
    d = this.y.mul(c.square().mul(c));
    b = b.subM(d);
    c = this.z.mul(c);
    return new sjcl.ecc.pointJac(this.curve, a, b, c);
  },
  doubl: function () {
    if (this.isIdentity) return this;
    var a = this.y.square(),
      b = a.mul(this.x.mul(4)),
      c = a.square().mul(8),
      a = this.z.square(),
      d =
        this.curve.a.toString() == new sjcl.bn(-3).toString()
          ? this.x.sub(a).mul(3).mul(this.x.add(a))
          : this.x.square().mul(3).add(a.square().mul(this.curve.a)),
      a = d.square().subM(b).subM(b),
      b = b.sub(a).mul(d).subM(c),
      c = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, a, b, c);
  },
  toAffine: function () {
    if (this.isIdentity || this.z.equals(0)) return new sjcl.ecc.point(this.curve);
    var a = this.z.inverse(),
      b = a.square();
    return new sjcl.ecc.point(this.curve, this.x.mul(b).fullReduce(), this.y.mul(b.mul(a)).fullReduce());
  },
  mult: function (a, b) {
    'number' === typeof a ? (a = [a]) : a.limbs !== t && (a = a.normalize().limbs);
    var c,
      d,
      e = new sjcl.ecc.point(this.curve).toJac(),
      f = b.multiples();
    for (c = a.length - 1; 0 <= c; c--)
      for (d = sjcl.bn.prototype.radix - 4; 0 <= d; d -= 4)
        e = e
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(f[(a[c] >> d) & 15]);
    return e;
  },
  mult2: function (a, b, c, d) {
    'number' === typeof a ? (a = [a]) : a.limbs !== t && (a = a.normalize().limbs);
    'number' === typeof c ? (c = [c]) : c.limbs !== t && (c = c.normalize().limbs);
    var e,
      f = new sjcl.ecc.point(this.curve).toJac();
    b = b.multiples();
    var g = d.multiples(),
      h,
      k;
    for (d = Math.max(a.length, c.length) - 1; 0 <= d; d--) {
      h = a[d] | 0;
      k = c[d] | 0;
      for (e = sjcl.bn.prototype.radix - 4; 0 <= e; e -= 4)
        f = f
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(b[(h >> e) & 15])
          .add(g[(k >> e) & 15]);
    }
    return f;
  },
  negate: function () {
    return this.toAffine().negate().toJac();
  },
  isValid: function () {
    var a = this.z.square(),
      b = a.square(),
      a = b.mul(a);
    return this.y.square().equals(this.curve.b.mul(a).add(this.x.mul(this.curve.a.mul(b).add(this.x.square()))));
  },
};
sjcl.ecc.curve = function (a, b, c, d, e, f) {
  this.field = a;
  this.r = new sjcl.bn(b);
  this.a = new a(c);
  this.b = new a(d);
  this.G = new sjcl.ecc.point(this, new a(e), new a(f));
};
sjcl.ecc.curve.prototype.fromBits = function (a) {
  var b = sjcl.bitArray,
    c = (this.field.prototype.exponent + 7) & -8;
  a = new sjcl.ecc.point(this, this.field.fromBits(b.bitSlice(a, 0, c)), this.field.fromBits(b.bitSlice(a, c, 2 * c)));
  a.isValid() || q(new sjcl.exception.corrupt('not on the curve!'));
  return a;
};
sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    '0xffffffffffffffffffffffff99def836146bc9b1b4d22831',
    -3,
    '0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',
    '0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012',
    '0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'
  ),
  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    '0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d',
    -3,
    '0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4',
    '0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21',
    '0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'
  ),
  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
    '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    -3,
    '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
    '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
  ),
  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    -3,
    '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'
  ),
  c521: new sjcl.ecc.curve(
    sjcl.bn.prime.p521,
    '0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409',
    -3,
    '0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
    '0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66',
    '0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650'
  ),
  k192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192k,
    '0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d',
    0,
    3,
    '0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d',
    '0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d'
  ),
  k224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224k,
    '0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7',
    0,
    5,
    '0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c',
    '0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5'
  ),
  k256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256k,
    '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    0,
    7,
    '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
  ),
};
sjcl.ecc.basicKey = {
  publicKey: function (a, b) {
    this.j = a;
    this.o = a.r.bitLength();
    this.D = b instanceof Array ? a.fromBits(b) : b;
    this.get = function () {
      var a = this.D.toBits(),
        b = sjcl.bitArray.bitLength(a),
        e = sjcl.bitArray.bitSlice(a, 0, b / 2),
        a = sjcl.bitArray.bitSlice(a, b / 2);
      return { x: e, y: a };
    };
  },
  secretKey: function (a, b) {
    this.j = a;
    this.o = a.r.bitLength();
    this.C = b;
    this.get = function () {
      return this.C.toBits();
    };
  },
};
sjcl.ecc.basicKey.generateKeys = function (a) {
  return function (b, c, d) {
    b = b || 0x100;
    'number' === typeof b &&
      ((b = sjcl.ecc.curves['c' + b]), b === t && q(new sjcl.exception.invalid('no such curve')));
    d = d || sjcl.bn.random(b.r, c);
    c = b.G.mult(d);
    return { pub: new sjcl.ecc[a].publicKey(b, c), sec: new sjcl.ecc[a].secretKey(b, d) };
  };
};
sjcl.ecc.elGamal = {
  generateKeys: sjcl.ecc.basicKey.generateKeys('elGamal'),
  publicKey: function (a, b) {
    sjcl.ecc.basicKey.publicKey.apply(this, arguments);
  },
  secretKey: function (a, b) {
    sjcl.ecc.basicKey.secretKey.apply(this, arguments);
  },
};
sjcl.ecc.elGamal.publicKey.prototype = {
  kem: function (a) {
    a = sjcl.bn.random(this.j.r, a);
    var b = this.j.G.mult(a).toBits();
    return { key: sjcl.hash.sha256.hash(this.D.mult(a).toBits()), tag: b };
  },
};
sjcl.ecc.elGamal.secretKey.prototype = {
  unkem: function (a) {
    return sjcl.hash.sha256.hash(this.j.fromBits(a).mult(this.C).toBits());
  },
  dh: function (a) {
    return sjcl.hash.sha256.hash(a.D.mult(this.C).toBits());
  },
  dhJavaEc: function (a) {
    return a.D.mult(this.C).x.toBits();
  },
};
sjcl.ecc.ecdsa = { generateKeys: sjcl.ecc.basicKey.generateKeys('ecdsa') };
sjcl.ecc.ecdsa.publicKey = function (a, b) {
  sjcl.ecc.basicKey.publicKey.apply(this, arguments);
};
sjcl.ecc.ecdsa.publicKey.prototype = {
  verify: function (a, b, c) {
    sjcl.bitArray.bitLength(a) > this.o && (a = sjcl.bitArray.clamp(a, this.o));
    var d = sjcl.bitArray,
      e = this.j.r,
      f = this.o,
      g = sjcl.bn.fromBits(d.bitSlice(b, 0, f)),
      d = sjcl.bn.fromBits(d.bitSlice(b, f, 2 * f)),
      h = c ? d : d.inverseMod(e),
      f = sjcl.bn.fromBits(a).mul(h).mod(e),
      h = g.mul(h).mod(e),
      f = this.j.G.mult2(f, h, this.D).x;
    if (g.equals(0) || d.equals(0) || g.greaterEquals(e) || d.greaterEquals(e) || !f.equals(g)) {
      if (c === t) return this.verify(a, b, u);
      q(new sjcl.exception.corrupt("signature didn't check out"));
    }
    return u;
  },
};
sjcl.ecc.ecdsa.secretKey = function (a, b) {
  sjcl.ecc.basicKey.secretKey.apply(this, arguments);
};
sjcl.ecc.ecdsa.secretKey.prototype = {
  sign: function (a, b, c, d) {
    sjcl.bitArray.bitLength(a) > this.o && (a = sjcl.bitArray.clamp(a, this.o));
    var e = this.j.r,
      f = e.bitLength();
    d = d || sjcl.bn.random(e.sub(1), b).add(1);
    b = this.j.G.mult(d).x.mod(e);
    a = sjcl.bn.fromBits(a).add(b.mul(this.C));
    c = c ? a.inverseMod(e).mul(d).mod(e) : a.mul(d.inverseMod(e)).mod(e);
    return sjcl.bitArray.concat(b.toBits(f), c.toBits(f));
  },
};
var random = [-625324409, -1863172196, -1745409890, -1513341554, 1970821986, -532843769, -200096675, -1271344660];
sjcl.random.addEntropy(random, 8 * 4 * random.length, 'crypto.randomBytes');
('use strict');
function q(a) {
  throw a;
}
var t = void 0,
  u = !0,
  v = !1;
var sjcl = {
  cipher: {},
  hash: {},
  keyexchange: {},
  mode: {},
  misc: {},
  codec: {},
  exception: {
    corrupt: function (a) {
      this.toString = function () {
        return 'CORRUPT: ' + this.message;
      };
      this.message = a;
    },
    invalid: function (a) {
      this.toString = function () {
        return 'INVALID: ' + this.message;
      };
      this.message = a;
    },
    bug: function (a) {
      this.toString = function () {
        return 'BUG: ' + this.message;
      };
      this.message = a;
    },
    notReady: function (a) {
      this.toString = function () {
        return 'NOT READY: ' + this.message;
      };
      this.message = a;
    },
  },
};
'undefined' !== typeof module && module.exports && (module.exports = sjcl);
'function' === typeof define &&
  define([], function () {
    return sjcl;
  });
sjcl.cipher.aes = function (a) {
  this.t[0][0][0] || this.Q();
  var b,
    c,
    d,
    e,
    f = this.t[0][4],
    g = this.t[1];
  b = a.length;
  var h = 1;
  4 !== b && 6 !== b && 8 !== b && q(new sjcl.exception.invalid('invalid aes key size'));
  this.d = [(d = a.slice(0)), (e = [])];
  for (a = b; a < 4 * b + 28; a++) {
    c = d[a - 1];
    if (0 === a % b || (8 === b && 4 === a % b))
      (c = (f[c >>> 24] << 24) ^ (f[(c >> 16) & 255] << 16) ^ (f[(c >> 8) & 255] << 8) ^ f[c & 255]),
        0 === a % b && ((c = (c << 8) ^ (c >>> 24) ^ (h << 24)), (h = (h << 1) ^ (283 * (h >> 7))));
    d[a] = d[a - b] ^ c;
  }
  for (b = 0; a; b++, a--)
    (c = d[b & 3 ? a : a - 4]),
      (e[b] =
        4 >= a || 4 > b
          ? c
          : g[0][f[c >>> 24]] ^ g[1][f[(c >> 16) & 255]] ^ g[2][f[(c >> 8) & 255]] ^ g[3][f[c & 255]]);
};
sjcl.cipher.aes.prototype = {
  encrypt: function (a) {
    return w(this, a, 0);
  },
  decrypt: function (a) {
    return w(this, a, 1);
  },
  t: [
    [[], [], [], [], []],
    [[], [], [], [], []],
  ],
  Q: function () {
    var a = this.t[0],
      b = this.t[1],
      c = a[4],
      d = b[4],
      e,
      f,
      g,
      h = [],
      k = [],
      l,
      n,
      m,
      p;
    for (e = 0; 0x100 > e; e++) k[(h[e] = (e << 1) ^ (283 * (e >> 7))) ^ e] = e;
    for (f = g = 0; !c[f]; f ^= l || 1, g = k[g] || 1) {
      m = g ^ (g << 1) ^ (g << 2) ^ (g << 3) ^ (g << 4);
      m = (m >> 8) ^ (m & 255) ^ 99;
      c[f] = m;
      d[m] = f;
      n = h[(e = h[(l = h[f])])];
      p = (0x1010101 * n) ^ (0x10001 * e) ^ (0x101 * l) ^ (0x1010100 * f);
      n = (0x101 * h[m]) ^ (0x1010100 * m);
      for (e = 0; 4 > e; e++) (a[e][f] = n = (n << 24) ^ (n >>> 8)), (b[e][m] = p = (p << 24) ^ (p >>> 8));
    }
    for (e = 0; 5 > e; e++) (a[e] = a[e].slice(0)), (b[e] = b[e].slice(0));
  },
};
function w(a, b, c) {
  4 !== b.length && q(new sjcl.exception.invalid('invalid aes block size'));
  var d = a.d[c],
    e = b[0] ^ d[0],
    f = b[c ? 3 : 1] ^ d[1],
    g = b[2] ^ d[2];
  b = b[c ? 1 : 3] ^ d[3];
  var h,
    k,
    l,
    n = d.length / 4 - 2,
    m,
    p = 4,
    s = [0, 0, 0, 0];
  h = a.t[c];
  a = h[0];
  var r = h[1],
    z = h[2],
    A = h[3],
    B = h[4];
  for (m = 0; m < n; m++)
    (h = a[e >>> 24] ^ r[(f >> 16) & 255] ^ z[(g >> 8) & 255] ^ A[b & 255] ^ d[p]),
      (k = a[f >>> 24] ^ r[(g >> 16) & 255] ^ z[(b >> 8) & 255] ^ A[e & 255] ^ d[p + 1]),
      (l = a[g >>> 24] ^ r[(b >> 16) & 255] ^ z[(e >> 8) & 255] ^ A[f & 255] ^ d[p + 2]),
      (b = a[b >>> 24] ^ r[(e >> 16) & 255] ^ z[(f >> 8) & 255] ^ A[g & 255] ^ d[p + 3]),
      (p += 4),
      (e = h),
      (f = k),
      (g = l);
  for (m = 0; 4 > m; m++)
    (s[c ? 3 & -m : m] =
      (B[e >>> 24] << 24) ^ (B[(f >> 16) & 255] << 16) ^ (B[(g >> 8) & 255] << 8) ^ B[b & 255] ^ d[p++]),
      (h = e),
      (e = f),
      (f = g),
      (g = b),
      (b = h);
  return s;
}
sjcl.bitArray = {
  bitSlice: function (a, b, c) {
    a = sjcl.bitArray.aa(a.slice(b / 32), 32 - (b & 31)).slice(1);
    return c === t ? a : sjcl.bitArray.clamp(a, c - b);
  },
  extract: function (a, b, c) {
    var d = Math.floor((-b - c) & 31);
    return (
      (((b + c - 1) ^ b) & -32 ? (a[(b / 32) | 0] << (32 - d)) ^ (a[(b / 32 + 1) | 0] >>> d) : a[(b / 32) | 0] >>> d) &
      ((1 << c) - 1)
    );
  },
  concat: function (a, b) {
    if (0 === a.length || 0 === b.length) return a.concat(b);
    var c = a[a.length - 1],
      d = sjcl.bitArray.getPartial(c);
    return 32 === d ? a.concat(b) : sjcl.bitArray.aa(b, d, c | 0, a.slice(0, a.length - 1));
  },
  bitLength: function (a) {
    var b = a.length;
    return 0 === b ? 0 : 32 * (b - 1) + sjcl.bitArray.getPartial(a[b - 1]);
  },
  clamp: function (a, b) {
    if (32 * a.length < b) return a;
    a = a.slice(0, Math.ceil(b / 32));
    var c = a.length;
    b &= 31;
    0 < c && b && (a[c - 1] = sjcl.bitArray.partial(b, a[c - 1] & (2147483648 >> (b - 1)), 1));
    return a;
  },
  partial: function (a, b, c) {
    return 32 === a ? b : (c ? b | 0 : b << (32 - a)) + 0x10000000000 * a;
  },
  getPartial: function (a) {
    return Math.round(a / 0x10000000000) || 32;
  },
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) return v;
    var c = 0,
      d;
    for (d = 0; d < a.length; d++) c |= a[d] ^ b[d];
    return 0 === c;
  },
  aa: function (a, b, c, d) {
    var e;
    e = 0;
    for (d === t && (d = []); 32 <= b; b -= 32) d.push(c), (c = 0);
    if (0 === b) return d.concat(a);
    for (e = 0; e < a.length; e++) d.push(c | (a[e] >>> b)), (c = a[e] << (32 - b));
    e = a.length ? a[a.length - 1] : 0;
    a = sjcl.bitArray.getPartial(e);
    d.push(sjcl.bitArray.partial((b + a) & 31, 32 < b + a ? c : d.pop(), 1));
    return d;
  },
  n: function (a, b) {
    return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
  },
  byteswapM: function (a) {
    var b, c;
    for (b = 0; b < a.length; ++b)
      (c = a[b]), (a[b] = (c >>> 24) | ((c >>> 8) & 0xff00) | ((c & 0xff00) << 8) | (c << 24));
    return a;
  },
};
sjcl.codec.utf8String = {
  fromBits: function (a) {
    var b = '',
      c = sjcl.bitArray.bitLength(a),
      d,
      e;
    for (d = 0; d < c / 8; d++) 0 === (d & 3) && (e = a[d / 4]), (b += String.fromCharCode(e >>> 24)), (e <<= 8);
    return decodeURIComponent(escape(b));
  },
  toBits: function (a) {
    a = unescape(encodeURIComponent(a));
    var b = [],
      c,
      d = 0;
    for (c = 0; c < a.length; c++) (d = (d << 8) | a.charCodeAt(c)), 3 === (c & 3) && (b.push(d), (d = 0));
    c & 3 && b.push(sjcl.bitArray.partial(8 * (c & 3), d));
    return b;
  },
};
sjcl.codec.hex = {
  fromBits: function (a) {
    var b = '',
      c;
    for (c = 0; c < a.length; c++) b += ((a[c] | 0) + 0xf00000000000).toString(16).substr(4);
    return b.substr(0, sjcl.bitArray.bitLength(a) / 4);
  },
  toBits: function (a) {
    var b,
      c = [],
      d;
    a = a.replace(/\s|0x/g, '');
    d = a.length;
    a += '00000000';
    for (b = 0; b < a.length; b += 8) c.push(parseInt(a.substr(b, 8), 16) ^ 0);
    return sjcl.bitArray.clamp(c, 4 * d);
  },
};
sjcl.codec.base64 = {
  V: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  fromBits: function (a, b, c) {
    var d = '',
      e = 0,
      f = sjcl.codec.base64.V,
      g = 0,
      h = sjcl.bitArray.bitLength(a);
    c && (f = f.substr(0, 62) + '-_');
    for (c = 0; 6 * d.length < h; )
      (d += f.charAt((g ^ (a[c] >>> e)) >>> 26)),
        6 > e ? ((g = a[c] << (6 - e)), (e += 26), c++) : ((g <<= 6), (e -= 6));
    for (; d.length & 3 && !b; ) d += '=';
    return d;
  },
  toBits: function (a, b) {
    a = a.replace(/\s|=/g, '');
    var c = [],
      d,
      e = 0,
      f = sjcl.codec.base64.V,
      g = 0,
      h;
    b && (f = f.substr(0, 62) + '-_');
    for (d = 0; d < a.length; d++)
      (h = f.indexOf(a.charAt(d))),
        0 > h && q(new sjcl.exception.invalid("this isn't base64!")),
        26 < e ? ((e -= 26), c.push(g ^ (h >>> e)), (g = h << (32 - e))) : ((e += 6), (g ^= h << (32 - e)));
    e & 56 && c.push(sjcl.bitArray.partial(e & 56, g, 1));
    return c;
  },
};
sjcl.codec.base64url = {
  fromBits: function (a) {
    return sjcl.codec.base64.fromBits(a, 1, 1);
  },
  toBits: function (a) {
    return sjcl.codec.base64.toBits(a, 1);
  },
};
sjcl.codec.bytes = {
  fromBits: function (a) {
    var b = [],
      c = sjcl.bitArray.bitLength(a),
      d,
      e;
    for (d = 0; d < c / 8; d++) 0 === (d & 3) && (e = a[d / 4]), b.push(e >>> 24), (e <<= 8);
    return b;
  },
  toBits: function (a) {
    var b = [],
      c,
      d = 0;
    for (c = 0; c < a.length; c++) (d = (d << 8) | a[c]), 3 === (c & 3) && (b.push(d), (d = 0));
    c & 3 && b.push(sjcl.bitArray.partial(8 * (c & 3), d));
    return b;
  },
};
sjcl.hash.sha256 = function (a) {
  this.d[0] || this.Q();
  a ? ((this.h = a.h.slice(0)), (this.f = a.f.slice(0)), (this.e = a.e)) : this.reset();
};
sjcl.hash.sha256.hash = function (a) {
  return new sjcl.hash.sha256().update(a).finalize();
};
sjcl.hash.sha256.prototype = {
  blockSize: 512,
  reset: function () {
    this.h = this.H.slice(0);
    this.f = [];
    this.e = 0;
    return this;
  },
  update: function (a) {
    'string' === typeof a && (a = sjcl.codec.utf8String.toBits(a));
    var b,
      c = (this.f = sjcl.bitArray.concat(this.f, a));
    b = this.e;
    a = this.e = b + sjcl.bitArray.bitLength(a);
    for (b = (512 + b) & -512; b <= a; b += 512) this.A(c.splice(0, 16));
    return this;
  },
  finalize: function () {
    var a,
      b = this.f,
      c = this.h,
      b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (a = b.length + 2; a & 15; a++) b.push(0);
    b.push(Math.floor(this.e / 4294967296));
    for (b.push(this.e | 0); b.length; ) this.A(b.splice(0, 16));
    this.reset();
    return c;
  },
  H: [],
  d: [],
  Q: function () {
    function a(a) {
      return (0x100000000 * (a - Math.floor(a))) | 0;
    }
    var b = 0,
      c = 2,
      d;
    a: for (; 64 > b; c++) {
      for (d = 2; d * d <= c; d++) if (0 === c % d) continue a;
      8 > b && (this.H[b] = a(Math.pow(c, 0.5)));
      this.d[b] = a(Math.pow(c, 1 / 3));
      b++;
    }
  },
  A: function (a) {
    var b,
      c,
      d = a.slice(0),
      e = this.h,
      f = this.d,
      g = e[0],
      h = e[1],
      k = e[2],
      l = e[3],
      n = e[4],
      m = e[5],
      p = e[6],
      s = e[7];
    for (a = 0; 64 > a; a++)
      16 > a
        ? (b = d[a])
        : ((b = d[(a + 1) & 15]),
          (c = d[(a + 14) & 15]),
          (b = d[a & 15] =
            (((b >>> 7) ^ (b >>> 18) ^ (b >>> 3) ^ (b << 25) ^ (b << 14)) +
              ((c >>> 17) ^ (c >>> 19) ^ (c >>> 10) ^ (c << 15) ^ (c << 13)) +
              d[a & 15] +
              d[(a + 9) & 15]) |
            0)),
        (b =
          b +
          s +
          ((n >>> 6) ^ (n >>> 11) ^ (n >>> 25) ^ (n << 26) ^ (n << 21) ^ (n << 7)) +
          (p ^ (n & (m ^ p))) +
          f[a]),
        (s = p),
        (p = m),
        (m = n),
        (n = (l + b) | 0),
        (l = k),
        (k = h),
        (h = g),
        (g =
          (b + ((h & k) ^ (l & (h ^ k))) + ((h >>> 2) ^ (h >>> 13) ^ (h >>> 22) ^ (h << 30) ^ (h << 19) ^ (h << 10))) |
          0);
    e[0] = (e[0] + g) | 0;
    e[1] = (e[1] + h) | 0;
    e[2] = (e[2] + k) | 0;
    e[3] = (e[3] + l) | 0;
    e[4] = (e[4] + n) | 0;
    e[5] = (e[5] + m) | 0;
    e[6] = (e[6] + p) | 0;
    e[7] = (e[7] + s) | 0;
  },
};
sjcl.hash.sha1 = function (a) {
  a ? ((this.h = a.h.slice(0)), (this.f = a.f.slice(0)), (this.e = a.e)) : this.reset();
};
sjcl.hash.sha1.hash = function (a) {
  return new sjcl.hash.sha1().update(a).finalize();
};
sjcl.hash.sha1.prototype = {
  blockSize: 512,
  reset: function () {
    this.h = this.H.slice(0);
    this.f = [];
    this.e = 0;
    return this;
  },
  update: function (a) {
    'string' === typeof a && (a = sjcl.codec.utf8String.toBits(a));
    var b,
      c = (this.f = sjcl.bitArray.concat(this.f, a));
    b = this.e;
    a = this.e = b + sjcl.bitArray.bitLength(a);
    for (b = (this.blockSize + b) & -this.blockSize; b <= a; b += this.blockSize) this.A(c.splice(0, 16));
    return this;
  },
  finalize: function () {
    var a,
      b = this.f,
      c = this.h,
      b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
    for (a = b.length + 2; a & 15; a++) b.push(0);
    b.push(Math.floor(this.e / 0x100000000));
    for (b.push(this.e | 0); b.length; ) this.A(b.splice(0, 16));
    this.reset();
    return c;
  },
  H: [1732584193, 4023233417, 2562383102, 271733878, 3285377520],
  d: [1518500249, 1859775393, 2400959708, 3395469782],
  A: function (a) {
    var b,
      c,
      d,
      e,
      f,
      g,
      h = a.slice(0),
      k = this.h;
    c = k[0];
    d = k[1];
    e = k[2];
    f = k[3];
    g = k[4];
    for (a = 0; 79 >= a; a++)
      16 <= a &&
        (h[a] =
          ((h[a - 3] ^ h[a - 8] ^ h[a - 14] ^ h[a - 16]) << 1) |
          ((h[a - 3] ^ h[a - 8] ^ h[a - 14] ^ h[a - 16]) >>> 31)),
        (b =
          19 >= a
            ? (d & e) | (~d & f)
            : 39 >= a
            ? d ^ e ^ f
            : 59 >= a
            ? (d & e) | (d & f) | (e & f)
            : 79 >= a
            ? d ^ e ^ f
            : t),
        (b = (((c << 5) | (c >>> 27)) + b + g + h[a] + this.d[Math.floor(a / 20)]) | 0),
        (g = f),
        (f = e),
        (e = (d << 30) | (d >>> 2)),
        (d = c),
        (c = b);
    k[0] = (k[0] + c) | 0;
    k[1] = (k[1] + d) | 0;
    k[2] = (k[2] + e) | 0;
    k[3] = (k[3] + f) | 0;
    k[4] = (k[4] + g) | 0;
  },
};
sjcl.mode.ccm = {
  name: 'ccm',
  I: [],
  listenProgress: function (a) {
    sjcl.mode.ccm.I.push(a);
  },
  unListenProgress: function (a) {
    a = sjcl.mode.ccm.I.indexOf(a);
    -1 < a && sjcl.mode.ccm.I.splice(a, 1);
  },
  ha: function (a) {
    var b = sjcl.mode.ccm.I.slice(),
      c;
    for (c = 0; c < b.length; c += 1) b[c](a);
  },
  encrypt: function (a, b, c, d, e) {
    var f,
      g = b.slice(0),
      h = sjcl.bitArray,
      k = h.bitLength(c) / 8,
      l = h.bitLength(g) / 8;
    e = e || 64;
    d = d || [];
    7 > k && q(new sjcl.exception.invalid('ccm: iv must be at least 7 bytes'));
    for (f = 2; 4 > f && l >>> (8 * f); f++);
    f < 15 - k && (f = 15 - k);
    c = h.clamp(c, 8 * (15 - f));
    b = sjcl.mode.ccm.X(a, b, c, d, e, f);
    g = sjcl.mode.ccm.B(a, g, c, b, e, f);
    return h.concat(g.data, g.tag);
  },
  decrypt: function (a, b, c, d, e) {
    e = e || 64;
    d = d || [];
    var f = sjcl.bitArray,
      g = f.bitLength(c) / 8,
      h = f.bitLength(b),
      k = f.clamp(b, h - e),
      l = f.bitSlice(b, h - e),
      h = (h - e) / 8;
    7 > g && q(new sjcl.exception.invalid('ccm: iv must be at least 7 bytes'));
    for (b = 2; 4 > b && h >>> (8 * b); b++);
    b < 15 - g && (b = 15 - g);
    c = f.clamp(c, 8 * (15 - b));
    k = sjcl.mode.ccm.B(a, k, c, l, e, b);
    a = sjcl.mode.ccm.X(a, k.data, c, d, e, b);
    f.equal(k.tag, a) || q(new sjcl.exception.corrupt("ccm: tag doesn't match"));
    return k.data;
  },
  pa: function (a, b, c, d, e, f) {
    var g = [],
      h = sjcl.bitArray,
      k = h.n;
    d = [h.partial(8, (b.length ? 64 : 0) | ((d - 2) << 2) | (f - 1))];
    d = h.concat(d, c);
    d[3] |= e;
    d = a.encrypt(d);
    if (b.length) {
      c = h.bitLength(b) / 8;
      65279 >= c ? (g = [h.partial(16, c)]) : 0xffffffff >= c && (g = h.concat([h.partial(16, 65534)], [c]));
      g = h.concat(g, b);
      for (b = 0; b < g.length; b += 4) d = a.encrypt(k(d, g.slice(b, b + 4).concat([0, 0, 0])));
    }
    return d;
  },
  X: function (a, b, c, d, e, f) {
    var g = sjcl.bitArray,
      h = g.n;
    e /= 8;
    (e % 2 || 4 > e || 16 < e) && q(new sjcl.exception.invalid('ccm: invalid tag length'));
    (0xffffffff < d.length || 0xffffffff < b.length) &&
      q(new sjcl.exception.bug("ccm: can't deal with 4GiB or more data"));
    c = sjcl.mode.ccm.pa(a, d, c, e, g.bitLength(b) / 8, f);
    for (d = 0; d < b.length; d += 4) c = a.encrypt(h(c, b.slice(d, d + 4).concat([0, 0, 0])));
    return g.clamp(c, 8 * e);
  },
  B: function (a, b, c, d, e, f) {
    var g,
      h = sjcl.bitArray;
    g = h.n;
    var k = b.length,
      l = h.bitLength(b),
      n = k / 50,
      m = n;
    c = h
      .concat([h.partial(8, f - 1)], c)
      .concat([0, 0, 0])
      .slice(0, 4);
    d = h.bitSlice(g(d, a.encrypt(c)), 0, e);
    if (!k) return { tag: d, data: [] };
    for (g = 0; g < k; g += 4)
      g > n && (sjcl.mode.ccm.ha(g / k), (n += m)),
        c[3]++,
        (e = a.encrypt(c)),
        (b[g] ^= e[0]),
        (b[g + 1] ^= e[1]),
        (b[g + 2] ^= e[2]),
        (b[g + 3] ^= e[3]);
    return { tag: d, data: h.clamp(b, l) };
  },
};
sjcl.mode.ocb2 = {
  name: 'ocb2',
  encrypt: function (a, b, c, d, e, f) {
    128 !== sjcl.bitArray.bitLength(c) && q(new sjcl.exception.invalid('ocb iv must be 128 bits'));
    var g,
      h = sjcl.mode.ocb2.T,
      k = sjcl.bitArray,
      l = k.n,
      n = [0, 0, 0, 0];
    c = h(a.encrypt(c));
    var m,
      p = [];
    d = d || [];
    e = e || 64;
    for (g = 0; g + 4 < b.length; g += 4)
      (m = b.slice(g, g + 4)), (n = l(n, m)), (p = p.concat(l(c, a.encrypt(l(c, m))))), (c = h(c));
    m = b.slice(g);
    b = k.bitLength(m);
    g = a.encrypt(l(c, [0, 0, 0, b]));
    m = k.clamp(l(m.concat([0, 0, 0]), g), b);
    n = l(n, l(m.concat([0, 0, 0]), g));
    n = a.encrypt(l(n, l(c, h(c))));
    d.length && (n = l(n, f ? d : sjcl.mode.ocb2.pmac(a, d)));
    return p.concat(k.concat(m, k.clamp(n, e)));
  },
  decrypt: function (a, b, c, d, e, f) {
    128 !== sjcl.bitArray.bitLength(c) && q(new sjcl.exception.invalid('ocb iv must be 128 bits'));
    e = e || 64;
    var g = sjcl.mode.ocb2.T,
      h = sjcl.bitArray,
      k = h.n,
      l = [0, 0, 0, 0],
      n = g(a.encrypt(c)),
      m,
      p,
      s = sjcl.bitArray.bitLength(b) - e,
      r = [];
    d = d || [];
    for (c = 0; c + 4 < s / 32; c += 4)
      (m = k(n, a.decrypt(k(n, b.slice(c, c + 4))))), (l = k(l, m)), (r = r.concat(m)), (n = g(n));
    p = s - 32 * c;
    m = a.encrypt(k(n, [0, 0, 0, p]));
    m = k(m, h.clamp(b.slice(c), p).concat([0, 0, 0]));
    l = k(l, m);
    l = a.encrypt(k(l, k(n, g(n))));
    d.length && (l = k(l, f ? d : sjcl.mode.ocb2.pmac(a, d)));
    h.equal(h.clamp(l, e), h.bitSlice(b, s)) || q(new sjcl.exception.corrupt("ocb: tag doesn't match"));
    return r.concat(h.clamp(m, p));
  },
  pmac: function (a, b) {
    var c,
      d = sjcl.mode.ocb2.T,
      e = sjcl.bitArray,
      f = e.n,
      g = [0, 0, 0, 0],
      h = a.encrypt([0, 0, 0, 0]),
      h = f(h, d(d(h)));
    for (c = 0; c + 4 < b.length; c += 4) (h = d(h)), (g = f(g, a.encrypt(f(h, b.slice(c, c + 4)))));
    c = b.slice(c);
    128 > e.bitLength(c) && ((h = f(h, d(h))), (c = e.concat(c, [-2147483648, 0, 0, 0])));
    g = f(g, c);
    return a.encrypt(f(d(f(h, d(h))), g));
  },
  T: function (a) {
    return [
      (a[0] << 1) ^ (a[1] >>> 31),
      (a[1] << 1) ^ (a[2] >>> 31),
      (a[2] << 1) ^ (a[3] >>> 31),
      (a[3] << 1) ^ (135 * (a[0] >>> 31)),
    ];
  },
};
sjcl.mode.gcm = {
  name: 'gcm',
  encrypt: function (a, b, c, d, e) {
    var f = b.slice(0);
    b = sjcl.bitArray;
    d = d || [];
    a = sjcl.mode.gcm.B(u, a, f, d, c, e || 128);
    return b.concat(a.data, a.tag);
  },
  decrypt: function (a, b, c, d, e) {
    var f = b.slice(0),
      g = sjcl.bitArray,
      h = g.bitLength(f);
    e = e || 128;
    d = d || [];
    e <= h ? ((b = g.bitSlice(f, h - e)), (f = g.bitSlice(f, 0, h - e))) : ((b = f), (f = []));
    a = sjcl.mode.gcm.B(v, a, f, d, c, e);
    g.equal(a.tag, b) || q(new sjcl.exception.corrupt("gcm: tag doesn't match"));
    return a.data;
  },
  ma: function (a, b) {
    var c,
      d,
      e,
      f,
      g,
      h = sjcl.bitArray.n;
    e = [0, 0, 0, 0];
    f = b.slice(0);
    for (c = 0; 128 > c; c++) {
      (d = 0 !== (a[Math.floor(c / 32)] & (1 << (31 - (c % 32))))) && (e = h(e, f));
      g = 0 !== (f[3] & 1);
      for (d = 3; 0 < d; d--) f[d] = (f[d] >>> 1) | ((f[d - 1] & 1) << 31);
      f[0] >>>= 1;
      g && (f[0] ^= -0x1f000000);
    }
    return e;
  },
  p: function (a, b, c) {
    var d,
      e = c.length;
    b = b.slice(0);
    for (d = 0; d < e; d += 4)
      (b[0] ^= 0xffffffff & c[d]),
        (b[1] ^= 0xffffffff & c[d + 1]),
        (b[2] ^= 0xffffffff & c[d + 2]),
        (b[3] ^= 0xffffffff & c[d + 3]),
        (b = sjcl.mode.gcm.ma(b, a));
    return b;
  },
  B: function (a, b, c, d, e, f) {
    var g,
      h,
      k,
      l,
      n,
      m,
      p,
      s,
      r = sjcl.bitArray;
    m = c.length;
    p = r.bitLength(c);
    s = r.bitLength(d);
    h = r.bitLength(e);
    g = b.encrypt([0, 0, 0, 0]);
    96 === h
      ? ((e = e.slice(0)), (e = r.concat(e, [1])))
      : ((e = sjcl.mode.gcm.p(g, [0, 0, 0, 0], e)),
        (e = sjcl.mode.gcm.p(g, e, [0, 0, Math.floor(h / 0x100000000), h & 0xffffffff])));
    h = sjcl.mode.gcm.p(g, [0, 0, 0, 0], d);
    n = e.slice(0);
    d = h.slice(0);
    a || (d = sjcl.mode.gcm.p(g, h, c));
    for (l = 0; l < m; l += 4)
      n[3]++, (k = b.encrypt(n)), (c[l] ^= k[0]), (c[l + 1] ^= k[1]), (c[l + 2] ^= k[2]), (c[l + 3] ^= k[3]);
    c = r.clamp(c, p);
    a && (d = sjcl.mode.gcm.p(g, h, c));
    a = [Math.floor(s / 0x100000000), s & 0xffffffff, Math.floor(p / 0x100000000), p & 0xffffffff];
    d = sjcl.mode.gcm.p(g, d, a);
    k = b.encrypt(e);
    d[0] ^= k[0];
    d[1] ^= k[1];
    d[2] ^= k[2];
    d[3] ^= k[3];
    return { tag: r.bitSlice(d, 0, f), data: c };
  },
};
sjcl.misc.hmac = function (a, b) {
  this.Y = b = b || sjcl.hash.sha256;
  var c = [[], []],
    d,
    e = b.prototype.blockSize / 32;
  this.w = [new b(), new b()];
  a.length > e && (a = b.hash(a));
  for (d = 0; d < e; d++) (c[0][d] = a[d] ^ 909522486), (c[1][d] = a[d] ^ 1549556828);
  this.w[0].update(c[0]);
  this.w[1].update(c[1]);
  this.S = new b(this.w[0]);
};
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (a) {
  this.ca && q(new sjcl.exception.invalid('encrypt on already updated hmac called!'));
  this.update(a);
  return this.digest(a);
};
sjcl.misc.hmac.prototype.reset = function () {
  this.S = new this.Y(this.w[0]);
  this.ca = v;
};
sjcl.misc.hmac.prototype.update = function (a) {
  this.ca = u;
  this.S.update(a);
};
sjcl.misc.hmac.prototype.digest = function () {
  var a = this.S.finalize(),
    a = new this.Y(this.w[1]).update(a).finalize();
  this.reset();
  return a;
};
sjcl.misc.pbkdf2 = function (a, b, c, d, e) {
  c = c || 1e3;
  (0 > d || 0 > c) && q(sjcl.exception.invalid('invalid params to pbkdf2'));
  'string' === typeof a && (a = sjcl.codec.utf8String.toBits(a));
  'string' === typeof b && (b = sjcl.codec.utf8String.toBits(b));
  e = e || sjcl.misc.hmac;
  a = new e(a);
  var f,
    g,
    h,
    k,
    l = [],
    n = sjcl.bitArray;
  for (k = 1; 32 * l.length < (d || 1); k++) {
    e = f = a.encrypt(n.concat(b, [k]));
    for (g = 1; g < c; g++) {
      f = a.encrypt(f);
      for (h = 0; h < f.length; h++) e[h] ^= f[h];
    }
    l = l.concat(e);
  }
  d && (l = n.clamp(l, d));
  return l;
};
sjcl.prng = function (a) {
  this.i = [new sjcl.hash.sha256()];
  this.q = [0];
  this.R = 0;
  this.J = {};
  this.P = 0;
  this.W = {};
  this.$ = this.k = this.s = this.ja = 0;
  this.d = [0, 0, 0, 0, 0, 0, 0, 0];
  this.m = [0, 0, 0, 0];
  this.N = t;
  this.O = a;
  this.F = v;
  this.M = { progress: {}, seeded: {} };
  this.u = this.ia = 0;
  this.K = 1;
  this.L = 2;
  this.ea = 0x10000;
  this.U = [0, 48, 64, 96, 128, 192, 0x100, 384, 512, 768, 1024];
  this.fa = 3e4;
  this.da = 80;
};
sjcl.prng.prototype = {
  randomWords: function (a, b) {
    var c = [],
      d;
    d = this.isReady(b);
    var e;
    d === this.u && q(new sjcl.exception.notReady("generator isn't seeded"));
    if (d & this.L) {
      d = !(d & this.K);
      e = [];
      var f = 0,
        g;
      this.$ = e[0] = new Date().valueOf() + this.fa;
      for (g = 0; 16 > g; g++) e.push((0x100000000 * Math.random()) | 0);
      for (
        g = 0;
        g < this.i.length &&
        !((e = e.concat(this.i[g].finalize())), (f += this.q[g]), (this.q[g] = 0), !d && this.R & (1 << g));
        g++
      );
      this.R >= 1 << this.i.length && (this.i.push(new sjcl.hash.sha256()), this.q.push(0));
      this.k -= f;
      f > this.s && (this.s = f);
      this.R++;
      this.d = sjcl.hash.sha256.hash(this.d.concat(e));
      this.N = new sjcl.cipher.aes(this.d);
      for (d = 0; 4 > d && !((this.m[d] = (this.m[d] + 1) | 0), this.m[d]); d++);
    }
    for (d = 0; d < a; d += 4) 0 === (d + 1) % this.ea && x(this), (e = y(this)), c.push(e[0], e[1], e[2], e[3]);
    x(this);
    return c.slice(0, a);
  },
  setDefaultParanoia: function (a, b) {
    0 === a &&
      'Setting paranoia=0 will ruin your security; use it only for testing' !== b &&
      q('Setting paranoia=0 will ruin your security; use it only for testing');
    this.O = a;
  },
  addEntropy: function (a, b, c) {
    c = c || 'user';
    var d,
      e,
      f = new Date().valueOf(),
      g = this.J[c],
      h = this.isReady(),
      k = 0;
    d = this.W[c];
    d === t && (d = this.W[c] = this.ja++);
    g === t && (g = this.J[c] = 0);
    this.J[c] = (this.J[c] + 1) % this.i.length;
    switch (typeof a) {
      case 'number':
        b === t && (b = 1);
        this.i[g].update([d, this.P++, 1, b, f, 1, a | 0]);
        break;
      case 'object':
        c = Object.prototype.toString.call(a);
        if ('[object Uint32Array]' === c) {
          e = [];
          for (c = 0; c < a.length; c++) e.push(a[c]);
          a = e;
        } else {
          '[object Array]' !== c && (k = 1);
          for (c = 0; c < a.length && !k; c++) 'number' !== typeof a[c] && (k = 1);
        }
        if (!k) {
          if (b === t) for (c = b = 0; c < a.length; c++) for (e = a[c]; 0 < e; ) b++, (e >>>= 1);
          this.i[g].update([d, this.P++, 2, b, f, a.length].concat(a));
        }
        break;
      case 'string':
        b === t && (b = a.length);
        this.i[g].update([d, this.P++, 3, b, f, a.length]);
        this.i[g].update(a);
        break;
      default:
        k = 1;
    }
    k && q(new sjcl.exception.bug('random: addEntropy only supports number, array of numbers or string'));
    this.q[g] += b;
    this.k += b;
    h === this.u &&
      (this.isReady() !== this.u && C('seeded', Math.max(this.s, this.k)), C('progress', this.getProgress()));
  },
  isReady: function (a) {
    a = this.U[a !== t ? a : this.O];
    return this.s && this.s >= a
      ? this.q[0] > this.da && new Date().valueOf() > this.$
        ? this.L | this.K
        : this.K
      : this.k >= a
      ? this.L | this.u
      : this.u;
  },
  getProgress: function (a) {
    a = this.U[a ? a : this.O];
    return this.s >= a ? 1 : this.k > a ? 1 : this.k / a;
  },
  startCollectors: function () {
    this.F ||
      ((this.c = {
        loadTimeCollector: D(this, this.oa),
        mouseCollector: D(this, this.qa),
        keyboardCollector: D(this, this.na),
        accelerometerCollector: D(this, this.ga),
        touchCollector: D(this, this.sa),
      }),
      window.addEventListener
        ? (window.addEventListener('load', this.c.loadTimeCollector, v),
          window.addEventListener('mousemove', this.c.mouseCollector, v),
          window.addEventListener('keypress', this.c.keyboardCollector, v),
          window.addEventListener('devicemotion', this.c.accelerometerCollector, v),
          window.addEventListener('touchmove', this.c.touchCollector, v))
        : document.attachEvent
        ? (document.attachEvent('onload', this.c.loadTimeCollector),
          document.attachEvent('onmousemove', this.c.mouseCollector),
          document.attachEvent('keypress', this.c.keyboardCollector))
        : q(new sjcl.exception.bug("can't attach event")),
      (this.F = u));
  },
  stopCollectors: function () {
    this.F &&
      (window.removeEventListener
        ? (window.removeEventListener('load', this.c.loadTimeCollector, v),
          window.removeEventListener('mousemove', this.c.mouseCollector, v),
          window.removeEventListener('keypress', this.c.keyboardCollector, v),
          window.removeEventListener('devicemotion', this.c.accelerometerCollector, v),
          window.removeEventListener('touchmove', this.c.touchCollector, v))
        : document.detachEvent &&
          (document.detachEvent('onload', this.c.loadTimeCollector),
          document.detachEvent('onmousemove', this.c.mouseCollector),
          document.detachEvent('keypress', this.c.keyboardCollector)),
      (this.F = v));
  },
  addEventListener: function (a, b) {
    this.M[a][this.ia++] = b;
  },
  removeEventListener: function (a, b) {
    var c,
      d,
      e = this.M[a],
      f = [];
    for (d in e) e.hasOwnProperty(d) && e[d] === b && f.push(d);
    for (c = 0; c < f.length; c++) (d = f[c]), delete e[d];
  },
  na: function () {
    E(1);
  },
  qa: function (a) {
    var b, c;
    try {
      (b = a.x || a.clientX || a.offsetX || 0), (c = a.y || a.clientY || a.offsetY || 0);
    } catch (d) {
      c = b = 0;
    }
    0 != b && 0 != c && sjcl.random.addEntropy([b, c], 2, 'mouse');
    E(0);
  },
  sa: function (a) {
    a = a.touches[0] || a.changedTouches[0];
    sjcl.random.addEntropy([a.pageX || a.clientX, a.pageY || a.clientY], 1, 'touch');
    E(0);
  },
  oa: function () {
    E(2);
  },
  ga: function (a) {
    a = a.accelerationIncludingGravity.x || a.accelerationIncludingGravity.y || a.accelerationIncludingGravity.z;
    if (window.orientation) {
      var b = window.orientation;
      'number' === typeof b && sjcl.random.addEntropy(b, 1, 'accelerometer');
    }
    a && sjcl.random.addEntropy(a, 2, 'accelerometer');
    E(0);
  },
};
function C(a, b) {
  var c,
    d = sjcl.random.M[a],
    e = [];
  for (c in d) d.hasOwnProperty(c) && e.push(d[c]);
  for (c = 0; c < e.length; c++) e[c](b);
}
function E(a) {
  'undefined' !== typeof window && window.performance && 'function' === typeof window.performance.now
    ? sjcl.random.addEntropy(window.performance.now(), a, 'loadtime')
    : sjcl.random.addEntropy(new Date().valueOf(), a, 'loadtime');
}
function x(a) {
  a.d = y(a).concat(y(a));
  a.N = new sjcl.cipher.aes(a.d);
}
function y(a) {
  for (var b = 0; 4 > b && !((a.m[b] = (a.m[b] + 1) | 0), a.m[b]); b++);
  return a.N.encrypt(a.m);
}
function D(a, b) {
  return function () {
    b.apply(a, arguments);
  };
}
sjcl.random = new sjcl.prng(6);
a: try {
  var F, G, H, I;
  if ((I = 'undefined' !== typeof module)) {
    var J;
    if ((J = module.exports)) {
      var K;
      try {
        K = require('crypto');
      } catch (L) {
        K = null;
      }
      J = (G = K) && G.randomBytes;
    }
    I = J;
  }
  if (I)
    (F = G.randomBytes(128)),
      (F = new Uint32Array(new Uint8Array(F).buffer)),
      sjcl.random.addEntropy(F, 1024, "crypto['randomBytes']");
  else if ('undefined' !== typeof window && 'undefined' !== typeof Uint32Array) {
    H = new Uint32Array(32);
    if (window.crypto && window.crypto.getRandomValues) window.crypto.getRandomValues(H);
    else if (window.msCrypto && window.msCrypto.getRandomValues) window.msCrypto.getRandomValues(H);
    else break a;
    sjcl.random.addEntropy(H, 1024, "crypto['getRandomValues']");
  }
} catch (M) {
  'undefined' !== typeof window &&
    window.console &&
    (console.log('There was an error collecting entropy from the browser:'), console.log(M));
}
sjcl.json = {
  defaults: { v: 1, iter: 1e3, ks: 128, ts: 64, mode: 'ccm', adata: '', cipher: 'aes' },
  la: function (a, b, c, d) {
    c = c || {};
    d = d || {};
    var e = sjcl.json,
      f = e.l({ iv: sjcl.random.randomWords(4, 0) }, e.defaults),
      g;
    e.l(f, c);
    c = f.adata;
    'string' === typeof f.salt && (f.salt = sjcl.codec.base64.toBits(f.salt));
    'string' === typeof f.iv && (f.iv = sjcl.codec.base64.toBits(f.iv));
    (!sjcl.mode[f.mode] ||
      !sjcl.cipher[f.cipher] ||
      ('string' === typeof a && 100 >= f.iter) ||
      (64 !== f.ts && 96 !== f.ts && 128 !== f.ts) ||
      (128 !== f.ks && 192 !== f.ks && 0x100 !== f.ks) ||
      2 > f.iv.length ||
      4 < f.iv.length) &&
      q(new sjcl.exception.invalid('json encrypt: invalid parameters'));
    'string' === typeof a
      ? ((g = sjcl.misc.cachedPbkdf2(a, f)), (a = g.key.slice(0, f.ks / 32)), (f.salt = g.salt))
      : sjcl.ecc &&
        a instanceof sjcl.ecc.elGamal.publicKey &&
        ((g = a.kem()), (f.kemtag = g.tag), (a = g.key.slice(0, f.ks / 32)));
    'string' === typeof b && (b = sjcl.codec.utf8String.toBits(b));
    'string' === typeof c && (f.adata = c = sjcl.codec.utf8String.toBits(c));
    g = new sjcl.cipher[f.cipher](a);
    e.l(d, f);
    d.key = a;
    f.ct =
      'ccm' === f.mode && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && b instanceof ArrayBuffer
        ? sjcl.arrayBuffer.ccm.encrypt(g, b, f.iv, c, f.ts)
        : sjcl.mode[f.mode].encrypt(g, b, f.iv, c, f.ts);
    return f;
  },
  encrypt: function (a, b, c, d) {
    var e = sjcl.json,
      f = e.la.apply(e, arguments);
    return e.encode(f);
  },
  ka: function (a, b, c, d) {
    c = c || {};
    d = d || {};
    var e = sjcl.json;
    b = e.l(e.l(e.l({}, e.defaults), b), c, u);
    var f, g;
    f = b.adata;
    'string' === typeof b.salt && (b.salt = sjcl.codec.base64.toBits(b.salt));
    'string' === typeof b.iv && (b.iv = sjcl.codec.base64.toBits(b.iv));
    (!sjcl.mode[b.mode] ||
      !sjcl.cipher[b.cipher] ||
      ('string' === typeof a && 100 >= b.iter) ||
      (64 !== b.ts && 96 !== b.ts && 128 !== b.ts) ||
      (128 !== b.ks && 192 !== b.ks && 0x100 !== b.ks) ||
      !b.iv ||
      2 > b.iv.length ||
      4 < b.iv.length) &&
      q(new sjcl.exception.invalid('json decrypt: invalid parameters'));
    'string' === typeof a
      ? ((g = sjcl.misc.cachedPbkdf2(a, b)), (a = g.key.slice(0, b.ks / 32)), (b.salt = g.salt))
      : sjcl.ecc &&
        a instanceof sjcl.ecc.elGamal.secretKey &&
        (a = a.unkem(sjcl.codec.base64.toBits(b.kemtag)).slice(0, b.ks / 32));
    'string' === typeof f && (f = sjcl.codec.utf8String.toBits(f));
    g = new sjcl.cipher[b.cipher](a);
    f =
      'ccm' === b.mode && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && b.ct instanceof ArrayBuffer
        ? sjcl.arrayBuffer.ccm.decrypt(g, b.ct, b.iv, b.tag, f, b.ts)
        : sjcl.mode[b.mode].decrypt(g, b.ct, b.iv, f, b.ts);
    e.l(d, b);
    d.key = a;
    return 1 === c.raw ? f : sjcl.codec.utf8String.fromBits(f);
  },
  decrypt: function (a, b, c, d) {
    var e = sjcl.json;
    return e.ka(a, e.decode(b), c, d);
  },
  encode: function (a) {
    var b,
      c = '{',
      d = '';
    for (b in a)
      if (a.hasOwnProperty(b))
        switch (
          (b.match(/^[a-z0-9]+$/i) || q(new sjcl.exception.invalid('json encode: invalid property name')),
          (c += d + '"' + b + '":'),
          (d = ','),
          typeof a[b])
        ) {
          case 'number':
          case 'boolean':
            c += a[b];
            break;
          case 'string':
            c += '"' + escape(a[b]) + '"';
            break;
          case 'object':
            c += '"' + sjcl.codec.base64.fromBits(a[b], 0) + '"';
            break;
          default:
            q(new sjcl.exception.bug('json encode: unsupported type'));
        }
    return c + '}';
  },
  decode: function (a) {
    a = a.replace(/\s/g, '');
    a.match(/^\{.*\}$/) || q(new sjcl.exception.invalid("json decode: this isn't json!"));
    a = a.replace(/^\{|\}$/g, '').split(/,/);
    var b = {},
      c,
      d;
    for (c = 0; c < a.length; c++)
      (d = a[c].match(/^\s*(?:(["']?)([a-z][a-z0-9]*)\1)\s*:\s*(?:(-?\d+)|"([a-z0-9+\/%*_.@=\-]*)"|(true|false))$/i)) ||
        q(new sjcl.exception.invalid("json decode: this isn't json!")),
        null != d[3]
          ? (b[d[2]] = parseInt(d[3], 10))
          : null != d[4]
          ? (b[d[2]] = d[2].match(/^(ct|adata|salt|iv)$/) ? sjcl.codec.base64.toBits(d[4]) : unescape(d[4]))
          : null != d[5] && (b[d[2]] = 'true' === d[5]);
    return b;
  },
  l: function (a, b, c) {
    a === t && (a = {});
    if (b === t) return a;
    for (var d in b)
      b.hasOwnProperty(d) &&
        (c && a[d] !== t && a[d] !== b[d] && q(new sjcl.exception.invalid('required parameter overridden')),
        (a[d] = b[d]));
    return a;
  },
  ua: function (a, b) {
    var c = {},
      d;
    for (d in a) a.hasOwnProperty(d) && a[d] !== b[d] && (c[d] = a[d]);
    return c;
  },
  ta: function (a, b) {
    var c = {},
      d;
    for (d = 0; d < b.length; d++) a[b[d]] !== t && (c[b[d]] = a[b[d]]);
    return c;
  },
};
sjcl.encrypt = sjcl.json.encrypt;
sjcl.decrypt = sjcl.json.decrypt;
sjcl.misc.ra = {};
sjcl.misc.cachedPbkdf2 = function (a, b) {
  var c = sjcl.misc.ra,
    d;
  b = b || {};
  d = b.iter || 1e3;
  c = c[a] = c[a] || {};
  d = c[d] = c[d] || { firstSalt: b.salt && b.salt.length ? b.salt.slice(0) : sjcl.random.randomWords(2, 0) };
  c = b.salt === t ? d.firstSalt : b.salt;
  d[c] = d[c] || sjcl.misc.pbkdf2(a, c, b.iter);
  return { key: d[c].slice(0), salt: c.slice(0) };
};
sjcl.bn = function (a) {
  this.initWith(a);
};
sjcl.bn.prototype = {
  radix: 24,
  maxMul: 8,
  g: sjcl.bn,
  copy: function () {
    return new this.g(this);
  },
  initWith: function (a) {
    var b = 0,
      c;
    switch (typeof a) {
      case 'object':
        this.limbs = a.limbs.slice(0);
        break;
      case 'number':
        this.limbs = [a];
        this.normalize();
        break;
      case 'string':
        a = a.replace(/^0x/, '');
        this.limbs = [];
        c = this.radix / 4;
        for (b = 0; b < a.length; b += c)
          this.limbs.push(parseInt(a.substring(Math.max(a.length - b - c, 0), a.length - b), 16));
        break;
      default:
        this.limbs = [0];
    }
    return this;
  },
  equals: function (a) {
    'number' === typeof a && (a = new this.g(a));
    var b = 0,
      c;
    this.fullReduce();
    a.fullReduce();
    for (c = 0; c < this.limbs.length || c < a.limbs.length; c++) b |= this.getLimb(c) ^ a.getLimb(c);
    return 0 === b;
  },
  getLimb: function (a) {
    return a >= this.limbs.length ? 0 : this.limbs[a];
  },
  greaterEquals: function (a) {
    'number' === typeof a && (a = new this.g(a));
    var b = 0,
      c = 0,
      d,
      e,
      f;
    for (d = Math.max(this.limbs.length, a.limbs.length) - 1; 0 <= d; d--)
      (e = this.getLimb(d)), (f = a.getLimb(d)), (c |= (f - e) & ~b), (b |= (e - f) & ~c);
    return (c | ~b) >>> 31;
  },
  toString: function () {
    this.fullReduce();
    var a = '',
      b,
      c,
      d = this.limbs;
    for (b = 0; b < this.limbs.length; b++) {
      for (c = d[b].toString(16); b < this.limbs.length - 1 && 6 > c.length; ) c = '0' + c;
      a = c + a;
    }
    return '0x' + a;
  },
  addM: function (a) {
    'object' !== typeof a && (a = new this.g(a));
    var b = this.limbs,
      c = a.limbs;
    for (a = b.length; a < c.length; a++) b[a] = 0;
    for (a = 0; a < c.length; a++) b[a] += c[a];
    return this;
  },
  doubleM: function () {
    var a,
      b = 0,
      c,
      d = this.radix,
      e = this.radixMask,
      f = this.limbs;
    for (a = 0; a < f.length; a++) (c = f[a]), (c = c + c + b), (f[a] = c & e), (b = c >> d);
    b && f.push(b);
    return this;
  },
  halveM: function () {
    var a,
      b = 0,
      c,
      d = this.radix,
      e = this.limbs;
    for (a = e.length - 1; 0 <= a; a--) (c = e[a]), (e[a] = (c + b) >> 1), (b = (c & 1) << d);
    e[e.length - 1] || e.pop();
    return this;
  },
  subM: function (a) {
    'object' !== typeof a && (a = new this.g(a));
    var b = this.limbs,
      c = a.limbs;
    for (a = b.length; a < c.length; a++) b[a] = 0;
    for (a = 0; a < c.length; a++) b[a] -= c[a];
    return this;
  },
  mod: function (a) {
    var b = !this.greaterEquals(new sjcl.bn(0));
    a = new sjcl.bn(a).normalize();
    var c = new sjcl.bn(this).normalize(),
      d = 0;
    for (b && (c = new sjcl.bn(0).subM(c).normalize()); c.greaterEquals(a); d++) a.doubleM();
    for (b && (c = a.sub(c).normalize()); 0 < d; d--) a.halveM(), c.greaterEquals(a) && c.subM(a).normalize();
    return c.trim();
  },
  inverseMod: function (a) {
    var b = new sjcl.bn(1),
      c = new sjcl.bn(0),
      d = new sjcl.bn(this),
      e = new sjcl.bn(a),
      f,
      g = 1;
    a.limbs[0] & 1 || q(new sjcl.exception.invalid('inverseMod: p must be odd'));
    do {
      d.limbs[0] & 1 &&
        (d.greaterEquals(e) || ((f = d), (d = e), (e = f), (f = b), (b = c), (c = f)),
        d.subM(e),
        d.normalize(),
        b.greaterEquals(c) || b.addM(a),
        b.subM(c));
      d.halveM();
      b.limbs[0] & 1 && b.addM(a);
      b.normalize();
      b.halveM();
      for (f = g = 0; f < d.limbs.length; f++) g |= d.limbs[f];
    } while (g);
    e.equals(1) || q(new sjcl.exception.invalid('inverseMod: p and x must be relatively prime'));
    return c;
  },
  add: function (a) {
    return this.copy().addM(a);
  },
  sub: function (a) {
    return this.copy().subM(a);
  },
  mul: function (a) {
    'number' === typeof a && (a = new this.g(a));
    var b,
      c = this.limbs,
      d = a.limbs,
      e = c.length,
      f = d.length,
      g = new this.g(),
      h = g.limbs,
      k,
      l = this.maxMul;
    for (b = 0; b < this.limbs.length + a.limbs.length + 1; b++) h[b] = 0;
    for (b = 0; b < e; b++) {
      k = c[b];
      for (a = 0; a < f; a++) h[b + a] += k * d[a];
      --l || ((l = this.maxMul), g.cnormalize());
    }
    return g.cnormalize().reduce();
  },
  square: function () {
    return this.mul(this);
  },
  power: function (a) {
    a = new sjcl.bn(a).normalize().trim().limbs;
    var b,
      c,
      d = new this.g(1),
      e = this;
    for (b = 0; b < a.length; b++)
      for (c = 0; c < this.radix; c++) {
        a[b] & (1 << c) && (d = d.mul(e));
        if (b == a.length - 1 && 0 == a[b] >> (c + 1)) break;
        e = e.square();
      }
    return d;
  },
  mulmod: function (a, b) {
    return this.mod(b).mul(a.mod(b)).mod(b);
  },
  powermod: function (a, b) {
    a = new sjcl.bn(a);
    b = new sjcl.bn(b);
    if (1 == (b.limbs[0] & 1)) {
      var c = this.montpowermod(a, b);
      if (c != v) return c;
    }
    for (var d, e = a.normalize().trim().limbs, f = new this.g(1), g = this, c = 0; c < e.length; c++)
      for (d = 0; d < this.radix; d++) {
        e[c] & (1 << d) && (f = f.mulmod(g, b));
        if (c == e.length - 1 && 0 == e[c] >> (d + 1)) break;
        g = g.mulmod(g, b);
      }
    return f;
  },
  montpowermod: function (a, b) {
    function c(a, b) {
      var c = b % a.radix;
      return (a.limbs[Math.floor(b / a.radix)] & (1 << c)) >> c;
    }
    function d(a, c) {
      var d,
        e,
        f = (1 << (l + 1)) - 1;
      d = a.mul(c);
      e = d.mul(s);
      e.limbs = e.limbs.slice(0, k.limbs.length);
      e.limbs.length == k.limbs.length && (e.limbs[k.limbs.length - 1] &= f);
      e = e.mul(b);
      e = d.add(e).normalize().trim();
      e.limbs = e.limbs.slice(k.limbs.length - 1);
      for (d = 0; d < e.limbs.length; d++)
        0 < d && (e.limbs[d - 1] |= (e.limbs[d] & f) << (g - l - 1)), (e.limbs[d] >>= l + 1);
      e.greaterEquals(b) && e.subM(b);
      return e;
    }
    a = new sjcl.bn(a).normalize().trim();
    b = new sjcl.bn(b);
    var e,
      f,
      g = this.radix,
      h = new this.g(1);
    e = this.copy();
    var k, l, n;
    n = a.bitLength();
    k = new sjcl.bn({
      limbs: b
        .copy()
        .normalize()
        .trim()
        .limbs.map(function () {
          return 0;
        }),
    });
    for (l = this.radix; 0 < l; l--)
      if (1 == ((b.limbs[b.limbs.length - 1] >> l) & 1)) {
        k.limbs[k.limbs.length - 1] = 1 << l;
        break;
      }
    if (0 == n) return this;
    n = 18 > n ? 1 : 48 > n ? 3 : 144 > n ? 4 : 768 > n ? 5 : 6;
    var m = k.copy(),
      p = b.copy();
    f = new sjcl.bn(1);
    for (var s = new sjcl.bn(0), r = k.copy(); r.greaterEquals(1); )
      r.halveM(), 0 == (f.limbs[0] & 1) ? (f.halveM(), s.halveM()) : (f.addM(p), f.halveM(), s.halveM(), s.addM(m));
    f = f.normalize();
    s = s.normalize();
    m.doubleM();
    p = m.mulmod(m, b);
    if (!m.mul(f).sub(b.mul(s)).equals(1)) return v;
    e = d(e, p);
    h = d(h, p);
    m = {};
    f = (1 << (n - 1)) - 1;
    m[1] = e.copy();
    m[2] = d(e, e);
    for (e = 1; e <= f; e++) m[2 * e + 1] = d(m[2 * e - 1], m[2]);
    for (e = a.bitLength() - 1; 0 <= e; )
      if (0 == c(a, e)) (h = d(h, h)), (e -= 1);
      else {
        for (p = e - n + 1; 0 == c(a, p); ) p++;
        r = 0;
        for (f = p; f <= e; f++) (r += c(a, f) << (f - p)), (h = d(h, h));
        h = d(h, m[r]);
        e = p - 1;
      }
    return d(h, 1);
  },
  trim: function () {
    var a = this.limbs,
      b;
    do b = a.pop();
    while (a.length && 0 === b);
    a.push(b);
    return this;
  },
  reduce: function () {
    return this;
  },
  fullReduce: function () {
    return this.normalize();
  },
  normalize: function () {
    var a = 0,
      b,
      c = this.placeVal,
      d = this.ipv,
      e,
      f = this.limbs,
      g = f.length,
      h = this.radixMask;
    for (b = 0; b < g || (0 !== a && -1 !== a); b++) (a = (f[b] || 0) + a), (e = f[b] = a & h), (a = (a - e) * d);
    -1 === a && (f[b - 1] -= c);
    return this;
  },
  cnormalize: function () {
    var a = 0,
      b,
      c = this.ipv,
      d,
      e = this.limbs,
      f = e.length,
      g = this.radixMask;
    for (b = 0; b < f - 1; b++) (a = e[b] + a), (d = e[b] = a & g), (a = (a - d) * c);
    e[b] += a;
    return this;
  },
  toBits: function (a) {
    this.fullReduce();
    a = a || this.exponent || this.bitLength();
    var b = Math.floor((a - 1) / 24),
      c = sjcl.bitArray,
      d = [c.partial(((a + 7) & -8) % this.radix || this.radix, this.getLimb(b))];
    for (b--; 0 <= b; b--) (d = c.concat(d, [c.partial(Math.min(this.radix, a), this.getLimb(b))])), (a -= this.radix);
    return d;
  },
  bitLength: function () {
    this.fullReduce();
    for (var a = this.radix * (this.limbs.length - 1), b = this.limbs[this.limbs.length - 1]; b; b >>>= 1) a++;
    return (a + 7) & -8;
  },
};
sjcl.bn.fromBits = function (a) {
  var b = new this(),
    c = [],
    d = sjcl.bitArray,
    e = this.prototype,
    f = Math.min(this.bitLength || 0x100000000, d.bitLength(a)),
    g = f % e.radix || e.radix;
  for (c[0] = d.extract(a, 0, g); g < f; g += e.radix) c.unshift(d.extract(a, g, e.radix));
  b.limbs = c;
  return b;
};
sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;
sjcl.bn.pseudoMersennePrime = function (a, b) {
  function c(a) {
    this.initWith(a);
  }
  var d = (c.prototype = new sjcl.bn()),
    e,
    f;
  e = d.modOffset = Math.ceil((f = a / d.radix));
  d.exponent = a;
  d.offset = [];
  d.factor = [];
  d.minOffset = e;
  d.fullMask = 0;
  d.fullOffset = [];
  d.fullFactor = [];
  d.modulus = c.modulus = new sjcl.bn(Math.pow(2, a));
  d.fullMask = 0 | -Math.pow(2, a % d.radix);
  for (e = 0; e < b.length; e++)
    (d.offset[e] = Math.floor(b[e][0] / d.radix - f)),
      (d.fullOffset[e] = Math.ceil(b[e][0] / d.radix - f)),
      (d.factor[e] = b[e][1] * Math.pow(0.5, a - b[e][0] + d.offset[e] * d.radix)),
      (d.fullFactor[e] = b[e][1] * Math.pow(0.5, a - b[e][0] + d.fullOffset[e] * d.radix)),
      d.modulus.addM(new sjcl.bn(Math.pow(2, b[e][0]) * b[e][1])),
      (d.minOffset = Math.min(d.minOffset, -d.offset[e]));
  d.g = c;
  d.modulus.cnormalize();
  d.reduce = function () {
    var a,
      b,
      c,
      d = this.modOffset,
      e = this.limbs,
      f = this.offset,
      p = this.offset.length,
      s = this.factor,
      r;
    for (a = this.minOffset; e.length > d; ) {
      c = e.pop();
      r = e.length;
      for (b = 0; b < p; b++) e[r + f[b]] -= s[b] * c;
      a--;
      a || (e.push(0), this.cnormalize(), (a = this.minOffset));
    }
    this.cnormalize();
    return this;
  };
  d.ba =
    -1 === d.fullMask
      ? d.reduce
      : function () {
          var a = this.limbs,
            b = a.length - 1,
            c,
            d;
          this.reduce();
          if (b === this.modOffset - 1) {
            d = a[b] & this.fullMask;
            a[b] -= d;
            for (c = 0; c < this.fullOffset.length; c++) a[b + this.fullOffset[c]] -= this.fullFactor[c] * d;
            this.normalize();
          }
        };
  d.fullReduce = function () {
    var a, b;
    this.ba();
    this.addM(this.modulus);
    this.addM(this.modulus);
    this.normalize();
    this.ba();
    for (b = this.limbs.length; b < this.modOffset; b++) this.limbs[b] = 0;
    a = this.greaterEquals(this.modulus);
    for (b = 0; b < this.limbs.length; b++) this.limbs[b] -= this.modulus.limbs[b] * a;
    this.cnormalize();
    return this;
  };
  d.inverse = function () {
    return this.power(this.modulus.sub(2));
  };
  c.fromBits = sjcl.bn.fromBits;
  return c;
};
var N = sjcl.bn.pseudoMersennePrime;
sjcl.bn.prime = {
  p127: N(127, [[0, -1]]),
  p25519: N(255, [[0, -19]]),
  p192k: N(192, [
    [32, -1],
    [12, -1],
    [8, -1],
    [7, -1],
    [6, -1],
    [3, -1],
    [0, -1],
  ]),
  p224k: N(224, [
    [32, -1],
    [12, -1],
    [11, -1],
    [9, -1],
    [7, -1],
    [4, -1],
    [1, -1],
    [0, -1],
  ]),
  p256k: N(0x100, [
    [32, -1],
    [9, -1],
    [8, -1],
    [7, -1],
    [6, -1],
    [4, -1],
    [0, -1],
  ]),
  p192: N(192, [
    [0, -1],
    [64, -1],
  ]),
  p224: N(224, [
    [0, 1],
    [96, -1],
  ]),
  p256: N(0x100, [
    [0, -1],
    [96, 1],
    [192, 1],
    [224, -1],
  ]),
  p384: N(384, [
    [0, -1],
    [32, 1],
    [96, -1],
    [128, -1],
  ]),
  p521: N(521, [[0, -1]]),
};
sjcl.bn.random = function (a, b) {
  'object' !== typeof a && (a = new sjcl.bn(a));
  for (var c, d, e = a.limbs.length, f = a.limbs[e - 1] + 1, g = new sjcl.bn(); ; ) {
    do (c = sjcl.random.randomWords(e, b)), 0 > c[e - 1] && (c[e - 1] += 0x100000000);
    while (Math.floor(c[e - 1] / f) === Math.floor(0x100000000 / f));
    c[e - 1] %= f;
    for (d = 0; d < e - 1; d++) c[d] &= a.radixMask;
    g.limbs = c;
    if (!g.greaterEquals(a)) return g;
  }
};
sjcl.ecc = {};
sjcl.ecc.point = function (a, b, c) {
  b === t
    ? (this.isIdentity = u)
    : (b instanceof sjcl.bn && (b = new a.field(b)),
      c instanceof sjcl.bn && (c = new a.field(c)),
      (this.x = b),
      (this.y = c),
      (this.isIdentity = v));
  this.curve = a;
};
sjcl.ecc.point.prototype = {
  toJac: function () {
    return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
  },
  mult: function (a) {
    return this.toJac().mult(a, this).toAffine();
  },
  mult2: function (a, b, c) {
    return this.toJac().mult2(a, this, b, c).toAffine();
  },
  multiples: function () {
    var a, b, c;
    if (this.Z === t) {
      c = this.toJac().doubl();
      a = this.Z = [new sjcl.ecc.point(this.curve), this, c.toAffine()];
      for (b = 3; 16 > b; b++) (c = c.add(this)), a.push(c.toAffine());
    }
    return this.Z;
  },
  negate: function () {
    var a = new this.curve.field(0).sub(this.y).normalize().reduce();
    return new sjcl.ecc.point(this.curve, this.x, a);
  },
  isValid: function () {
    return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },
  toBits: function () {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  },
};
sjcl.ecc.pointJac = function (a, b, c, d) {
  b === t ? (this.isIdentity = u) : ((this.x = b), (this.y = c), (this.z = d), (this.isIdentity = v));
  this.curve = a;
};
sjcl.ecc.pointJac.prototype = {
  add: function (a) {
    var b, c, d, e;
    this.curve !== a.curve && q("sjcl['ecc']['add'](): Points must be on the same curve to add them!");
    if (this.isIdentity) return a.toJac();
    if (a.isIdentity) return this;
    b = this.z.square();
    c = a.x.mul(b).subM(this.x);
    if (c.equals(0)) return this.y.equals(a.y.mul(b.mul(this.z))) ? this.doubl() : new sjcl.ecc.pointJac(this.curve);
    b = a.y.mul(b.mul(this.z)).subM(this.y);
    d = c.square();
    a = b.square();
    e = c.square().mul(c).addM(this.x.add(this.x).mul(d));
    a = a.subM(e);
    b = this.x.mul(d).subM(a).mul(b);
    d = this.y.mul(c.square().mul(c));
    b = b.subM(d);
    c = this.z.mul(c);
    return new sjcl.ecc.pointJac(this.curve, a, b, c);
  },
  doubl: function () {
    if (this.isIdentity) return this;
    var a = this.y.square(),
      b = a.mul(this.x.mul(4)),
      c = a.square().mul(8),
      a = this.z.square(),
      d =
        this.curve.a.toString() == new sjcl.bn(-3).toString()
          ? this.x.sub(a).mul(3).mul(this.x.add(a))
          : this.x.square().mul(3).add(a.square().mul(this.curve.a)),
      a = d.square().subM(b).subM(b),
      b = b.sub(a).mul(d).subM(c),
      c = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, a, b, c);
  },
  toAffine: function () {
    if (this.isIdentity || this.z.equals(0)) return new sjcl.ecc.point(this.curve);
    var a = this.z.inverse(),
      b = a.square();
    return new sjcl.ecc.point(this.curve, this.x.mul(b).fullReduce(), this.y.mul(b.mul(a)).fullReduce());
  },
  mult: function (a, b) {
    'number' === typeof a ? (a = [a]) : a.limbs !== t && (a = a.normalize().limbs);
    var c,
      d,
      e = new sjcl.ecc.point(this.curve).toJac(),
      f = b.multiples();
    for (c = a.length - 1; 0 <= c; c--)
      for (d = sjcl.bn.prototype.radix - 4; 0 <= d; d -= 4)
        e = e
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(f[(a[c] >> d) & 15]);
    return e;
  },
  mult2: function (a, b, c, d) {
    'number' === typeof a ? (a = [a]) : a.limbs !== t && (a = a.normalize().limbs);
    'number' === typeof c ? (c = [c]) : c.limbs !== t && (c = c.normalize().limbs);
    var e,
      f = new sjcl.ecc.point(this.curve).toJac();
    b = b.multiples();
    var g = d.multiples(),
      h,
      k;
    for (d = Math.max(a.length, c.length) - 1; 0 <= d; d--) {
      h = a[d] | 0;
      k = c[d] | 0;
      for (e = sjcl.bn.prototype.radix - 4; 0 <= e; e -= 4)
        f = f
          .doubl()
          .doubl()
          .doubl()
          .doubl()
          .add(b[(h >> e) & 15])
          .add(g[(k >> e) & 15]);
    }
    return f;
  },
  negate: function () {
    return this.toAffine().negate().toJac();
  },
  isValid: function () {
    var a = this.z.square(),
      b = a.square(),
      a = b.mul(a);
    return this.y.square().equals(this.curve.b.mul(a).add(this.x.mul(this.curve.a.mul(b).add(this.x.square()))));
  },
};
sjcl.ecc.curve = function (a, b, c, d, e, f) {
  this.field = a;
  this.r = new sjcl.bn(b);
  this.a = new a(c);
  this.b = new a(d);
  this.G = new sjcl.ecc.point(this, new a(e), new a(f));
};
sjcl.ecc.curve.prototype.fromBits = function (a) {
  var b = sjcl.bitArray,
    c = (this.field.prototype.exponent + 7) & -8;
  a = new sjcl.ecc.point(this, this.field.fromBits(b.bitSlice(a, 0, c)), this.field.fromBits(b.bitSlice(a, c, 2 * c)));
  a.isValid() || q(new sjcl.exception.corrupt('not on the curve!'));
  return a;
};
sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    '0xffffffffffffffffffffffff99def836146bc9b1b4d22831',
    -3,
    '0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1',
    '0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012',
    '0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811'
  ),
  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    '0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d',
    -3,
    '0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4',
    '0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21',
    '0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'
  ),
  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
    '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
    -3,
    '0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
    '0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
    '0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
  ),
  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
    -3,
    '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'
  ),
  c521: new sjcl.ecc.curve(
    sjcl.bn.prime.p521,
    '0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409',
    -3,
    '0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00',
    '0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66',
    '0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650'
  ),
  k192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192k,
    '0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d',
    0,
    3,
    '0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d',
    '0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d'
  ),
  k224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224k,
    '0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7',
    0,
    5,
    '0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c',
    '0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5'
  ),
  k256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256k,
    '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    0,
    7,
    '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
  ),
};
sjcl.ecc.basicKey = {
  publicKey: function (a, b) {
    this.j = a;
    this.o = a.r.bitLength();
    this.D = b instanceof Array ? a.fromBits(b) : b;
    this.get = function () {
      var a = this.D.toBits(),
        b = sjcl.bitArray.bitLength(a),
        e = sjcl.bitArray.bitSlice(a, 0, b / 2),
        a = sjcl.bitArray.bitSlice(a, b / 2);
      return { x: e, y: a };
    };
  },
  secretKey: function (a, b) {
    this.j = a;
    this.o = a.r.bitLength();
    this.C = b;
    this.get = function () {
      return this.C.toBits();
    };
  },
};
sjcl.ecc.basicKey.generateKeys = function (a) {
  return function (b, c, d) {
    b = b || 0x100;
    'number' === typeof b &&
      ((b = sjcl.ecc.curves['c' + b]), b === t && q(new sjcl.exception.invalid('no such curve')));
    d = d || sjcl.bn.random(b.r, c);
    c = b.G.mult(d);
    return { pub: new sjcl.ecc[a].publicKey(b, c), sec: new sjcl.ecc[a].secretKey(b, d) };
  };
};
sjcl.ecc.elGamal = {
  generateKeys: sjcl.ecc.basicKey.generateKeys('elGamal'),
  publicKey: function (a, b) {
    sjcl.ecc.basicKey.publicKey.apply(this, arguments);
  },
  secretKey: function (a, b) {
    sjcl.ecc.basicKey.secretKey.apply(this, arguments);
  },
};
sjcl.ecc.elGamal.publicKey.prototype = {
  kem: function (a) {
    a = sjcl.bn.random(this.j.r, a);
    var b = this.j.G.mult(a).toBits();
    return { key: sjcl.hash.sha256.hash(this.D.mult(a).toBits()), tag: b };
  },
};
sjcl.ecc.elGamal.secretKey.prototype = {
  unkem: function (a) {
    return sjcl.hash.sha256.hash(this.j.fromBits(a).mult(this.C).toBits());
  },
  dh: function (a) {
    return sjcl.hash.sha256.hash(a.D.mult(this.C).toBits());
  },
  dhJavaEc: function (a) {
    return a.D.mult(this.C).x.toBits();
  },
};
sjcl.ecc.ecdsa = { generateKeys: sjcl.ecc.basicKey.generateKeys('ecdsa') };
sjcl.ecc.ecdsa.publicKey = function (a, b) {
  sjcl.ecc.basicKey.publicKey.apply(this, arguments);
};
sjcl.ecc.ecdsa.publicKey.prototype = {
  verify: function (a, b, c) {
    sjcl.bitArray.bitLength(a) > this.o && (a = sjcl.bitArray.clamp(a, this.o));
    var d = sjcl.bitArray,
      e = this.j.r,
      f = this.o,
      g = sjcl.bn.fromBits(d.bitSlice(b, 0, f)),
      d = sjcl.bn.fromBits(d.bitSlice(b, f, 2 * f)),
      h = c ? d : d.inverseMod(e),
      f = sjcl.bn.fromBits(a).mul(h).mod(e),
      h = g.mul(h).mod(e),
      f = this.j.G.mult2(f, h, this.D).x;
    if (g.equals(0) || d.equals(0) || g.greaterEquals(e) || d.greaterEquals(e) || !f.equals(g)) {
      if (c === t) return this.verify(a, b, u);
      q(new sjcl.exception.corrupt("signature didn't check out"));
    }
    return u;
  },
};
sjcl.ecc.ecdsa.secretKey = function (a, b) {
  sjcl.ecc.basicKey.secretKey.apply(this, arguments);
};
sjcl.ecc.ecdsa.secretKey.prototype = {
  sign: function (a, b, c, d) {
    sjcl.bitArray.bitLength(a) > this.o && (a = sjcl.bitArray.clamp(a, this.o));
    var e = this.j.r,
      f = e.bitLength();
    d = d || sjcl.bn.random(e.sub(1), b).add(1);
    b = this.j.G.mult(d).x.mod(e);
    a = sjcl.bn.fromBits(a).add(b.mul(this.C));
    c = c ? a.inverseMod(e).mul(d).mod(e) : a.mul(d.inverseMod(e)).mod(e);
    return sjcl.bitArray.concat(b.toBits(f), c.toBits(f));
  },
};
var random = [-625324409, -1863172196, -1745409890, -1513341554, 1970821986, -532843769, -200096675, -1271344660];
sjcl.random.addEntropy(random, 8 * 4 * random.length, 'crypto.randomBytes');
console.log(sjcl);
