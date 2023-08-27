const WebSdkEncryptionSupport = {
    None: 1,
    Encoding: 2,
    Encryption: 3,
    AESEncryption: 4,
};
function traceSdk(...args) {
    if (envSdk.debug) {
        console.log(...args);
    }
}
class WebChannelOptions {
    constructor(options = {}) {
        this._version = WebSdkEncryptionSupport.AESEncryption;
        this.debug = options.debug || false;
        if (!!options.version) {
            this.version = options.version;
        }
    }
    get version() {
        return this._version;
    }
    set version(v) {
        if (!v || !Object.values(WebSdkEncryptionSupport).includes(v)) {
            throw new Error("invalid WebSdkEncryptionSupport");
        }
        if (envSdk.version >= WebSdkEncryptionSupport.AESEncryption && !isCryptoSupported()) {
            envSdk.version = WebSdkEncryptionSupport.Encryption; // if AES encryption is not supported by Browser, set data encryption to old one.
        }
        this._version = v;
    }
}
function isCryptoSupported() {
    return (typeof globalThis.crypto !== 'undefined') && globalThis.crypto.subtle;
}
const envSdk = {
    debug: false,
    version: 4,
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Basic JavaScript BN library - subset useful for RSA encryption.
 * Copyright (c) 2005  Tom Wu
 * All Rights Reserved.
 * See "LICENSE" for details.
 */
// @ts-nocheck
class BigInteger {
    constructor(a, b, c) {
        if (a != null) {
            if ("number" == typeof a) {
                this.fromNumber(a, b, c);
            }
            else if (b == null && "string" != typeof a) {
                this.fromString(a, 256);
            }
            else {
                this.fromString(a, b); // tm: we are using only params (string, number)
            }
        }
    }
    // (protected: bnpCopyTo) copy this to r
    copyTo(r) {
        for (var i = this.t - 1; i >= 0; --i) {
            r[i] = this[i];
        }
        r.t = this.t;
        r.s = this.s;
    }
    // (protected: bnpFromInt) set from integer value x, -DV <= x < DV
    fromInt(x) {
        this.t = 1;
        this.s = (x < 0) ? -1 : 0;
        if (x > 0)
            this[0] = x;
        else if (x < -1)
            this[0] = x + this.DV;
        else
            this.t = 0;
    }
    // (protected: bnpFromString) set from string and radix
    fromString(s, b) {
        var k;
        if (b == 16)
            k = 4;
        else if (b == 8)
            k = 3;
        else if (b == 256)
            k = 8; // byte array
        else if (b == 2)
            k = 1;
        else if (b == 32)
            k = 5;
        else if (b == 4)
            k = 2;
        else {
            this.fromRadix(s, b);
            return;
        }
        this.t = 0;
        this.s = 0;
        var i = s.length, mi = false, sh = 0;
        while (--i >= 0) {
            var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
            if (x < 0) {
                if (s.charAt(i) == "-")
                    mi = true;
                continue;
            }
            mi = false;
            if (sh == 0)
                this[this.t++] = x;
            else if (sh + k > this.DB) {
                this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                this[this.t++] = (x >> (this.DB - sh));
            }
            else
                this[this.t - 1] |= x << sh;
            sh += k;
            if (sh >= this.DB)
                sh -= this.DB;
        }
        if (k == 8 && (s[0] & 0x80) != 0) {
            this.s = -1;
            if (sh > 0)
                this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
        }
        this.clamp();
        if (mi)
            BigInteger.ZERO.subTo(this, this);
    }
    // (protected: bnpClamp) clamp off excess high words
    clamp() {
        var c = this.s & this.DM;
        while (this.t > 0 && this[this.t - 1] == c)
            --this.t;
    }
    // (public: bnToString) return string representation in given radix
    toString(b = 10) {
        if (this.s < 0) {
            return "-" + this.negate().toString(b);
        }
        var k;
        if (b == 16)
            k = 4;
        else if (b == 8)
            k = 3;
        else if (b == 2)
            k = 1;
        else if (b == 32)
            k = 5;
        else if (b == 4)
            k = 2;
        else
            return this.toRadix(b);
        var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
        var p = this.DB - (i * this.DB) % k;
        if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) > 0) {
                m = true;
                r = int2char(d);
            }
            while (i >= 0) {
                if (p < k) {
                    d = (this[i] & ((1 << p) - 1)) << (k - p);
                    d |= this[--i] >> (p += this.DB - k);
                }
                else {
                    d = (this[i] >> (p -= k)) & km;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if (d > 0)
                    m = true;
                if (m)
                    r += int2char(d);
            }
        }
        return m ? r : "0";
    }
    // (public: bnNegate) -this
    negate() {
        var r = nbi();
        BigInteger.ZERO.subTo(this, r);
        return r;
    }
    // (public: bnAbs) |this|
    abs() {
        return (this.s < 0) ? this.negate() : this;
    }
    // (public: bnCompareTo) return + if this > a, - if this < a, 0 if equal
    compareTo(a) {
        var r = this.s - a.s;
        if (r != 0)
            return r;
        var i = this.t;
        r = i - a.t;
        if (r != 0)
            return (this.s < 0) ? -r : r;
        while (--i >= 0)
            if ((r = this[i] - a[i]) != 0)
                return r;
        return 0;
    }
    // (public: bnBitLength) return the number of bits in "this"
    bitLength() {
        if (this.t <= 0)
            return 0;
        return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
    }
    // (protected: bnpDLShiftTo) r = this << n*DB
    dlShiftTo(n, r) {
        var i;
        for (i = this.t - 1; i >= 0; --i)
            r[i + n] = this[i];
        for (i = n - 1; i >= 0; --i)
            r[i] = 0;
        r.t = this.t + n;
        r.s = this.s;
    }
    // (protected: bnpDRShiftTo) r = this >> n*DB
    drShiftTo(n, r) {
        for (var i = n; i < this.t; ++i)
            r[i - n] = this[i];
        r.t = Math.max(this.t - n, 0);
        r.s = this.s;
    }
    // (protected: bnpLShiftTo) r = this << n
    lShiftTo(n, r) {
        var bs = n % this.DB;
        var cbs = this.DB - bs;
        var bm = (1 << cbs) - 1;
        var ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
        for (i = this.t - 1; i >= 0; --i) {
            r[i + ds + 1] = (this[i] >> cbs) | c;
            c = (this[i] & bm) << bs;
        }
        for (i = ds - 1; i >= 0; --i)
            r[i] = 0;
        r[ds] = c;
        r.t = this.t + ds + 1;
        r.s = this.s;
        r.clamp();
    }
    // (protected: bnpRShiftTo) r = this >> n
    rShiftTo(n, r) {
        r.s = this.s;
        var ds = Math.floor(n / this.DB);
        if (ds >= this.t) {
            r.t = 0;
            return;
        }
        var bs = n % this.DB;
        var cbs = this.DB - bs;
        var bm = (1 << bs) - 1;
        r[0] = this[ds] >> bs;
        for (var i = ds + 1; i < this.t; ++i) {
            r[i - ds - 1] |= (this[i] & bm) << cbs;
            r[i - ds] = this[i] >> bs;
        }
        if (bs > 0)
            r[this.t - ds - 1] |= (this.s & bm) << cbs;
        r.t = this.t - ds;
        r.clamp();
    }
    // (protected: bnpSubTo) r = this - a
    subTo(a, r) {
        var i = 0, c = 0, m = Math.min(a.t, this.t);
        while (i < m) {
            c += this[i] - a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < this.t) {
            c -= a.s;
            while (i < this.t) {
                c += this[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += this.s;
        }
        else {
            c += this.s;
            while (i < a.t) {
                c -= a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c -= a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c < -1)
            r[i++] = this.DV + c;
        else if (c > 0)
            r[i++] = c;
        r.t = i;
        r.clamp();
    }
    // (protected: bnpMultiplyTo) r = this * a, r != this,a (HAC 14.12)
    // "this" should be the larger one if appropriate.
    multiplyTo(a, r) {
        var x = this.abs(), y = a.abs();
        var i = x.t;
        r.t = i + y.t;
        while (--i >= 0)
            r[i] = 0;
        for (i = 0; i < y.t; ++i)
            r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
        r.s = 0;
        r.clamp();
        if (this.s != a.s)
            BigInteger.ZERO.subTo(r, r);
    }
    // (protected: bnpSquareTo) r = this^2, r != this (HAC 14.16)
    squareTo(r) {
        var x = this.abs();
        var i = r.t = 2 * x.t;
        while (--i >= 0)
            r[i] = 0;
        for (i = 0; i < x.t - 1; ++i) {
            var c = x.am(i, x[i], r, 2 * i, 0, 1);
            if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                r[i + x.t] -= x.DV;
                r[i + x.t + 1] = 1;
            }
        }
        if (r.t > 0)
            r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
        r.s = 0;
        r.clamp();
    }
    // (protected: bnpDivRemTo) divide this by m, quotient and remainder to q, r (HAC 14.20)
    // r != q, this != m.  q or r may be null.
    divRemTo(m, q, r) {
        var pm = m.abs();
        if (pm.t <= 0)
            return;
        var pt = this.abs();
        if (pt.t < pm.t) {
            if (q != null)
                q.fromInt(0);
            if (r != null)
                this.copyTo(r);
            return;
        }
        if (r == null)
            r = nbi();
        var y = nbi(), ts = this.s, ms = m.s;
        var nsh = this.DB - nbits(pm[pm.t - 1]); // normalize modulus
        if (nsh > 0) {
            pm.lShiftTo(nsh, y);
            pt.lShiftTo(nsh, r);
        }
        else {
            pm.copyTo(y);
            pt.copyTo(r);
        }
        var ys = y.t;
        var y0 = y[ys - 1];
        if (y0 == 0)
            return;
        var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
        var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
        var i = r.t, j = i - ys, t = (q == null) ? nbi() : q;
        y.dlShiftTo(j, t);
        if (r.compareTo(t) >= 0) {
            r[r.t++] = 1;
            r.subTo(t, r);
        }
        BigInteger.ONE.dlShiftTo(ys, t);
        t.subTo(y, y); // "negative" y so we can replace sub with am later
        while (y.t < ys)
            y[y.t++] = 0;
        while (--j >= 0) {
            // Estimate quotient digit
            var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
            if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
                y.dlShiftTo(j, t);
                r.subTo(t, r);
                while (r[i] < --qd)
                    r.subTo(t, r);
            }
        }
        if (q != null) {
            r.drShiftTo(ys, q);
            if (ts != ms)
                BigInteger.ZERO.subTo(q, q);
        }
        r.t = ys;
        r.clamp();
        if (nsh > 0)
            r.rShiftTo(nsh, r); // Denormalize remainder
        if (ts < 0)
            BigInteger.ZERO.subTo(r, r);
    }
    // (public: bnMod) this mod a
    mod(a) {
        var r = nbi();
        this.abs().divRemTo(a, null, r);
        if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
            a.subTo(r, r);
        return r;
    }
    // (protected: bnpInvDigit) return "-1/this % 2^DB"; useful for Mont. reduction
    // justification:
    //         xy == 1 (mod m)
    //         xy =  1+km
    //   xy(2-xy) = (1+km)(1-km)
    // x[y(2-xy)] = 1-k^2m^2
    // x[y(2-xy)] == 1 (mod m^2)
    // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
    // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
    // JS multiply "overflows" differently from C/C++, so care is needed here.
    invDigit() {
        if (this.t < 1)
            return 0;
        var x = this[0];
        if ((x & 1) == 0)
            return 0;
        var y = x & 3; // y == 1/x mod 2^2
        y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
        y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
        y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
        // last step - calculate inverse mod DV directly;
        // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
        y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
        // we really want the negative inverse, and -DV < y < DV
        return (y > 0) ? this.DV - y : -y;
    }
    // (protected: bnpIsEven) true iff this is even
    isEven() {
        return ((this.t > 0) ? (this[0] & 1) : this.s) == 0;
    }
    // (protected: bnpExp) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
    exp(e, z) {
        if (e > 0xffffffff || e < 1)
            return BigInteger.ONE;
        var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
        g.copyTo(r);
        while (--i >= 0) {
            z.sqrTo(r, r2);
            if ((e & (1 << i)) > 0)
                z.mulTo(r2, g, r);
            else {
                var t = r;
                r = r2;
                r2 = t;
            }
        }
        return z.revert(r);
    }
    // (public: bnModPowInt) this^e % m, 0 <= e < 2^32
    modPowInt(e, m) {
        var z;
        if (e < 256 || m.isEven())
            z = new Classic(m);
        else
            z = new Montgomery(m);
        return this.exp(e, z);
    }
    // Copyright (c) 2005-2009  Tom Wu
    // All Rights Reserved.
    // See "LICENSE" for details.
    // Extended JavaScript BN functions, required for RSA private ops.
    // Version 1.1: new BigInteger("0", 10) returns "proper" zero
    // Version 1.2: square() API, isProbablePrime fix
    // (public: bnClone)
    clone() {
        var r = nbi();
        this.copyTo(r);
        return r;
    }
    // (public: bnIntValue) return value as integer
    intValue() {
        if (this.s < 0) {
            if (this.t == 1)
                return this[0] - this.DV;
            else if (this.t == 0)
                return -1;
        }
        else if (this.t == 1)
            return this[0];
        else if (this.t == 0)
            return 0;
        // assumes 16 < DB < 32
        return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
    }
    // (public: bnByteValue) return value as byte
    byteValue() {
        return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
    }
    // (public: bnShortValue) return value as short (assumes DB>=16)
    shortValue() {
        return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
    }
    // (protected: bnpChunkSize) return x s.t. r^x < DV
    chunkSize(r) {
        return Math.floor(Math.LN2 * this.DB / Math.log(r));
    }
    // (public: bnSigNum) 0 if this == 0, 1 if this > 0
    signum() {
        if (this.s < 0)
            return -1;
        else if (this.t <= 0 || (this.t == 1 && this[0] <= 0))
            return 0;
        else
            return 1;
    }
    // (protected: bnpToRadix) convert to radix string
    toRadix(b) {
        if (b == null)
            b = 10;
        if (this.signum() == 0 || b < 2 || b > 36)
            return "0";
        var cs = this.chunkSize(b);
        var a = Math.pow(b, cs);
        var d = nbv(a), y = nbi(), z = nbi(), r = "";
        this.divRemTo(d, y, z);
        while (y.signum() > 0) {
            r = (a + z.intValue()).toString(b).substr(1) + r;
            y.divRemTo(d, y, z);
        }
        return z.intValue().toString(b) + r;
    }
    // (protected: bnpFromRadix) convert from radix string
    fromRadix(s, b) {
        this.fromInt(0);
        if (b == null)
            b = 10;
        var cs = this.chunkSize(b);
        var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
        for (var i = 0; i < s.length; ++i) {
            var x = intAt(s, i);
            if (x < 0) {
                if (s.charAt(i) == "-" && this.signum() == 0)
                    mi = true;
                continue;
            }
            w = b * w + x;
            if (++j >= cs) {
                this.dMultiply(d);
                this.dAddOffset(w, 0);
                j = 0;
                w = 0;
            }
        }
        if (j > 0) {
            this.dMultiply(Math.pow(b, j));
            this.dAddOffset(w, 0);
        }
        if (mi)
            BigInteger.ZERO.subTo(this, this);
    }
    // (protected: bnpFromNumber) alternate constructor
    fromNumber(a, b, c) {
        if ("number" == typeof b) {
            // new BigInteger(int,int,RNG)
            if (a < 2) {
                this.fromInt(1);
            }
            else {
                this.fromNumber(a, c);
                if (!this.testBit(a - 1)) { // force MSB set
                    this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
                }
                if (this.isEven()) {
                    this.dAddOffset(1, 0); // force odd
                }
                while (!this.isProbablePrime(b)) {
                    this.dAddOffset(2, 0);
                    if (this.bitLength() > a) {
                        this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
                    }
                }
            }
        }
        else {
            // new BigInteger(int,RNG)
            var x = new Array();
            var t = a & 7;
            x.length = (a >> 3) + 1;
            ///@ts-ignore
            b.nextBytes(x); //tm: this is java function and this path wont work. later
            if (t > 0) {
                x[0] &= ((1 << t) - 1);
            }
            else {
                x[0] = 0;
            }
            this.fromString(x, 256);
        }
    }
    // (public: bnToByteArray) convert to bigendian byte array
    toByteArray() {
        var i = this.t, r = new Array();
        r[0] = this.s;
        var p = this.DB - (i * this.DB) % 8, d, k = 0;
        if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
                r[k++] = d | (this.s << (this.DB - p));
            while (i >= 0) {
                if (p < 8) {
                    d = (this[i] & ((1 << p) - 1)) << (8 - p);
                    d |= this[--i] >> (p += this.DB - 8);
                }
                else {
                    d = (this[i] >> (p -= 8)) & 0xff;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if ((d & 0x80) != 0)
                    d |= -256;
                if (k == 0 && (this.s & 0x80) != (d & 0x80))
                    ++k;
                if (k > 0 || d != this.s)
                    r[k++] = d;
            }
        }
        return r;
    }
    // (public: bnEquals)
    equals(a) {
        return (this.compareTo(a) == 0);
    }
    // (public: bnMin)
    min(a) {
        return (this.compareTo(a) < 0) ? this : a;
    }
    // (public: bnMax)
    max(a) {
        return (this.compareTo(a) > 0) ? this : a;
    }
    // (protected: bnpBitwiseTo) r = this op a (bitwise)
    bitwiseTo(a, op, r) {
        var i, f, m = Math.min(a.t, this.t);
        for (i = 0; i < m; ++i)
            r[i] = op(this[i], a[i]);
        if (a.t < this.t) {
            f = a.s & this.DM;
            for (i = m; i < this.t; ++i)
                r[i] = op(this[i], f);
            r.t = this.t;
        }
        else {
            f = this.s & this.DM;
            for (i = m; i < a.t; ++i)
                r[i] = op(f, a[i]);
            r.t = a.t;
        }
        r.s = op(this.s, a.s);
        r.clamp();
    }
    // (public: bnAnd) this & a
    and(a) {
        var r = nbi();
        this.bitwiseTo(a, op_and, r);
        return r;
    }
    // (public: bnOr) this | a
    or(a) {
        var r = nbi();
        this.bitwiseTo(a, op_or, r);
        return r;
    }
    // (public: bnXor) this ^ a
    xor(a) {
        var r = nbi();
        this.bitwiseTo(a, op_xor, r);
        return r;
    }
    // (public: bnAndNot) this & ~a
    andNot(a) {
        var r = nbi();
        this.bitwiseTo(a, op_andnot, r);
        return r;
    }
    // (public: bnNot) ~this
    not() {
        var r = nbi();
        for (var i = 0; i < this.t; ++i)
            r[i] = this.DM & ~this[i];
        r.t = this.t;
        r.s = ~this.s;
        return r;
    }
    // (public: bnShiftLeft) this << n
    shiftLeft(n) {
        var r = nbi();
        if (n < 0)
            this.rShiftTo(-n, r);
        else
            this.lShiftTo(n, r);
        return r;
    }
    // (public: bnShiftRight) this >> n
    shiftRight(n) {
        var r = nbi();
        if (n < 0)
            this.lShiftTo(-n, r);
        else
            this.rShiftTo(n, r);
        return r;
    }
    // (public: bnGetLowestSetBit) returns index of lowest 1-bit (or -1 if none)
    getLowestSetBit() {
        for (var i = 0; i < this.t; ++i)
            if (this[i] != 0)
                return i * this.DB + lbit(this[i]);
        if (this.s < 0)
            return this.t * this.DB;
        return -1;
    }
    // (public: bnBitCount) return number of set bits
    bitCount() {
        var r = 0, x = this.s & this.DM;
        for (var i = 0; i < this.t; ++i)
            r += cbit(this[i] ^ x);
        return r;
    }
    // (public: bnTestBit) true iff nth bit is set
    testBit(n) {
        var j = Math.floor(n / this.DB);
        if (j >= this.t)
            return (this.s != 0);
        return ((this[j] & (1 << (n % this.DB))) != 0);
    }
    // (protected: bnpChangeBit) this op (1<<n)
    changeBit(n, op) {
        var r = BigInteger.ONE.shiftLeft(n);
        this.bitwiseTo(r, op, r);
        return r;
    }
    // (public: bnSetBit) this | (1<<n)
    setBit(n) {
        return this.changeBit(n, op_or);
    }
    // (public: bnClearBit) this & ~(1<<n)
    clearBit(n) {
        return this.changeBit(n, op_andnot);
    }
    // (public: bnFlipBit) this ^ (1<<n)
    flipBit(n) {
        return this.changeBit(n, op_xor);
    }
    // (protected: bnpAddTo) r = this + a
    addTo(a, r) {
        var i = 0, c = 0, m = Math.min(a.t, this.t);
        while (i < m) {
            c += this[i] + a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < this.t) {
            c += a.s;
            while (i < this.t) {
                c += this[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += this.s;
        }
        else {
            c += this.s;
            while (i < a.t) {
                c += a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c > 0)
            r[i++] = c;
        else if (c < -1)
            r[i++] = this.DV + c;
        r.t = i;
        r.clamp();
    }
    // (public: bnAdd) this + a
    add(a) {
        var r = nbi();
        this.addTo(a, r);
        return r;
    }
    // (public: bnSubtract) this - a
    subtract(a) {
        var r = nbi();
        this.subTo(a, r);
        return r;
    }
    // (public: bnMultiply) this * a
    multiply(a) {
        var r = nbi();
        this.multiplyTo(a, r);
        return r;
    }
    // (public: bnSquare) this^2 (JSBN-specific extension)
    square() {
        var r = nbi();
        this.squareTo(r);
        return r;
    }
    // (public: bnDivide) this / a
    divide(a) {
        var r = nbi();
        this.divRemTo(a, r, null);
        return r;
    }
    // (public: bnRemainder) this % a
    remainder(a) {
        var r = nbi();
        this.divRemTo(a, null, r);
        return r;
    }
    // (public: bnDivideAndRemainder) [this/a,this%a]
    divideAndRemainder(a) {
        var q = nbi(), r = nbi();
        this.divRemTo(a, q, r);
        return new Array(q, r);
    }
    // (protected: bnpDMultiply) this *= n, this >= 0, 1 < n < DV
    dMultiply(n) {
        this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
        ++this.t;
        this.clamp();
    }
    // (protected: bnpDAddOffset) this += n << w words, this >= 0
    dAddOffset(n, w) {
        if (n == 0)
            return;
        while (this.t <= w)
            this[this.t++] = 0;
        this[w] += n;
        while (this[w] >= this.DV) {
            this[w] -= this.DV;
            if (++w >= this.t)
                this[this.t++] = 0;
            ++this[w];
        }
    }
    // (public: bnPow) this^e
    pow(e) {
        return this.exp(e, new NullExp());
    }
    // (protected: bnpMultiplyLowerTo) r = lower n words of "this * a", a.t <= n // "this" should be the larger one if appropriate.
    multiplyLowerTo(a, n, r) {
        var i = Math.min(this.t + a.t, n);
        r.s = 0; // assumes a,this >= 0
        r.t = i;
        while (i > 0)
            r[--i] = 0;
        var j;
        for (j = r.t - this.t; i < j; ++i)
            r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
        for (j = Math.min(a.t, n); i < j; ++i)
            this.am(0, a[i], r, i, 0, n - i);
        r.clamp();
    }
    // (protected: bnpMultiplyUpperTo) r = "this * a" without lower n words, n > 0 // "this" should be the larger one if appropriate.
    multiplyUpperTo(a, n, r) {
        --n;
        var i = r.t = this.t + a.t - n;
        r.s = 0; // assumes a,this >= 0
        while (--i >= 0)
            r[i] = 0;
        for (i = Math.max(n - this.t, 0); i < a.t; ++i)
            r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
        r.clamp();
        r.drShiftTo(1, r);
    }
    // (public: bnModPow) this^e % m (HAC 14.85)
    modPow(e, m) {
        var i = e.bitLength(), k, r = nbv(1), z;
        if (i <= 0)
            return r;
        else if (i < 18)
            k = 1;
        else if (i < 48)
            k = 3;
        else if (i < 144)
            k = 4;
        else if (i < 768)
            k = 5;
        else
            k = 6;
        if (i < 8)
            z = new Classic(m);
        else if (m.isEven())
            z = new Barrett(m);
        else
            z = new Montgomery(m);
        // precomputation
        var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
        g[1] = z.convert(this);
        if (k > 1) {
            var g2 = nbi();
            z.sqrTo(g[1], g2);
            while (n <= km) {
                g[n] = nbi();
                z.mulTo(g2, g[n - 2], g[n]);
                n += 2;
            }
        }
        var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
        i = nbits(e[j]) - 1;
        while (j >= 0) {
            if (i >= k1)
                w = (e[j] >> (i - k1)) & km;
            else {
                w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                if (j > 0)
                    w |= e[j - 1] >> (this.DB + i - k1);
            }
            n = k;
            while ((w & 1) == 0) {
                w >>= 1;
                --n;
            }
            if ((i -= n) < 0) {
                i += this.DB;
                --j;
            }
            if (is1) { // ret == 1, don't bother squaring or multiplying it
                g[w].copyTo(r);
                is1 = false;
            }
            else {
                while (n > 1) {
                    z.sqrTo(r, r2);
                    z.sqrTo(r2, r);
                    n -= 2;
                }
                if (n > 0)
                    z.sqrTo(r, r2);
                else {
                    t = r;
                    r = r2;
                    r2 = t;
                }
                z.mulTo(r2, g[w], r);
            }
            while (j >= 0 && (e[j] & (1 << i)) == 0) {
                z.sqrTo(r, r2);
                t = r;
                r = r2;
                r2 = t;
                if (--i < 0) {
                    i = this.DB - 1;
                    --j;
                }
            }
        }
        return z.revert(r);
    }
    // (public: bnGCD) gcd(this,a) (HAC 14.54)
    gcd(a) {
        var x = (this.s < 0) ? this.negate() : this.clone();
        var y = (a.s < 0) ? a.negate() : a.clone();
        if (x.compareTo(y) < 0) {
            var t = x;
            x = y;
            y = t;
        }
        var i = x.getLowestSetBit(), g = y.getLowestSetBit();
        if (g < 0)
            return x;
        if (i < g)
            g = i;
        if (g > 0) {
            x.rShiftTo(g, x);
            y.rShiftTo(g, y);
        }
        while (x.signum() > 0) {
            if ((i = x.getLowestSetBit()) > 0)
                x.rShiftTo(i, x);
            if ((i = y.getLowestSetBit()) > 0)
                y.rShiftTo(i, y);
            if (x.compareTo(y) >= 0) {
                x.subTo(y, x);
                x.rShiftTo(1, x);
            }
            else {
                y.subTo(x, y);
                y.rShiftTo(1, y);
            }
        }
        if (g > 0)
            y.lShiftTo(g, y);
        return y;
    }
    // (protected: bnpModInt) this % n, n < 2^26
    modInt(n) {
        if (n <= 0)
            return 0;
        var d = this.DV % n, r = (this.s < 0) ? n - 1 : 0;
        if (this.t > 0)
            if (d == 0)
                r = this[0] % n;
            else
                for (var i = this.t - 1; i >= 0; --i)
                    r = (d * r + this[i]) % n;
        return r;
    }
    // (public: bnModInverse) 1/this % m (HAC 14.61)
    modInverse(m) {
        var ac = m.isEven();
        if ((this.isEven() && ac) || m.signum() == 0)
            return BigInteger.ZERO;
        var u = m.clone(), v = this.clone();
        var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
        while (u.signum() != 0) {
            while (u.isEven()) {
                u.rShiftTo(1, u);
                if (ac) {
                    if (!a.isEven() || !b.isEven()) {
                        a.addTo(this, a);
                        b.subTo(m, b);
                    }
                    a.rShiftTo(1, a);
                }
                else if (!b.isEven())
                    b.subTo(m, b);
                b.rShiftTo(1, b);
            }
            while (v.isEven()) {
                v.rShiftTo(1, v);
                if (ac) {
                    if (!c.isEven() || !d.isEven()) {
                        c.addTo(this, c);
                        d.subTo(m, d);
                    }
                    c.rShiftTo(1, c);
                }
                else if (!d.isEven())
                    d.subTo(m, d);
                d.rShiftTo(1, d);
            }
            if (u.compareTo(v) >= 0) {
                u.subTo(v, u);
                if (ac)
                    a.subTo(c, a);
                b.subTo(d, b);
            }
            else {
                v.subTo(u, v);
                if (ac)
                    c.subTo(a, c);
                d.subTo(b, d);
            }
        }
        if (v.compareTo(BigInteger.ONE) != 0)
            return BigInteger.ZERO;
        if (d.compareTo(m) >= 0)
            return d.subtract(m);
        if (d.signum() < 0)
            d.addTo(m, d);
        else
            return d;
        if (d.signum() < 0)
            return d.add(m);
        else
            return d;
    }
    // (public: bnIsProbablePrime) test primality with certainty >= 1-.5^t
    isProbablePrime(t) {
        var i, x = this.abs();
        if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
            for (i = 0; i < lowprimes.length; ++i)
                if (x[0] == lowprimes[i])
                    return true;
            return false;
        }
        if (x.isEven())
            return false;
        i = 1;
        while (i < lowprimes.length) {
            var m = lowprimes[i], j = i + 1;
            while (j < lowprimes.length && m < lplim)
                m *= lowprimes[j++];
            m = x.modInt(m);
            while (i < j)
                if (m % lowprimes[i++] == 0)
                    return false;
        }
        return x.millerRabin(t);
    }
    // (protected: bnpMillerRabin) true if probably prime (HAC 4.24, Miller-Rabin)
    millerRabin(t) {
        var n1 = this.subtract(BigInteger.ONE);
        var k = n1.getLowestSetBit();
        if (k <= 0)
            return false;
        var r = n1.shiftRight(k);
        t = (t + 1) >> 1;
        if (t > lowprimes.length)
            t = lowprimes.length;
        var a = nbi();
        for (var i = 0; i < t; ++i) {
            //Pick bases at random, instead of starting at 2
            a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
            var y = a.modPow(r, this);
            if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
                var j = 1;
                while (j++ < k && y.compareTo(n1) != 0) {
                    y = y.modPowInt(2, this);
                    if (y.compareTo(BigInteger.ONE) == 0)
                        return false;
                }
                if (y.compareTo(n1) != 0)
                    return false;
            }
        }
        return true;
    }
} //class BigInteger
// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
// return new, unset BigInteger
function nbi() {
    return new BigInteger(null);
}
// Bits per digit
var dbits;
// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.
// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i, x, w, j, c, n) {
    while (--n >= 0) {
        var v = x * this[i++] + w[j] + c;
        c = Math.floor(v / 0x4000000);
        w[j++] = v & 0x3ffffff;
    }
    return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i, x, w, j, c, n) {
    var xl = x & 0x7fff, xh = x >> 15;
    while (--n >= 0) {
        var l = this[i] & 0x7fff;
        var h = this[i++] >> 15;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
        c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
        w[j++] = l & 0x3fffffff;
    }
    return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i, x, w, j, c, n) {
    var xl = x & 0x3fff, xh = x >> 14;
    while (--n >= 0) {
        var l = this[i] & 0x3fff;
        var h = this[i++] >> 14;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
        c = (l >> 28) + (m >> 14) + xh * h;
        w[j++] = l & 0xfffffff;
    }
    return c;
}
if ((navigator.appName == "Microsoft Internet Explorer")) {
    BigInteger.prototype.am = am2;
    dbits = 30;
}
else if ((navigator.appName != "Netscape")) {
    BigInteger.prototype.am = am1;
    dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
    BigInteger.prototype.am = am3;
    dbits = 28;
}
/////////////////////////////////////////
BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1 << dbits) - 1);
BigInteger.prototype.DV = (1 << dbits);
var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;
// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr, vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv)
    BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv)
    BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv)
    BI_RC[rr++] = vv;
function int2char(n) { return BI_RM.charAt(n); }
function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return (c == null) ? -1 : c;
}
// return bigint initialized to value
function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
}
// returns bit length of the integer x
function nbits(x) {
    var r = 1, t;
    if ((t = x >>> 16) != 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 8) != 0) {
        x = t;
        r += 8;
    }
    if ((t = x >> 4) != 0) {
        x = t;
        r += 4;
    }
    if ((t = x >> 2) != 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) != 0) {
        x = t;
        r += 1;
    }
    return r;
}
class Classic {
    constructor(m) {
        this.m = m;
        this.m = m;
    }
    convert(x) {
        if (x.s < 0 || x.compareTo(this.m) >= 0) {
            return x.mod(this.m);
        }
        else {
            return x;
        }
    }
    revert(x) {
        return x;
    }
    reduce(x) {
        x.divRemTo(this.m, null, x);
    }
    mulTo(x, y, r) {
        x.multiplyTo(y, r);
        this.reduce(r);
    }
    sqrTo(x, r) {
        x.squareTo(r);
        this.reduce(r);
    }
}
class Montgomery {
    constructor(m) {
        this.m = m;
        this.m = m;
        this.mp = m.invDigit();
        this.mpl = this.mp & 0x7fff;
        this.mph = this.mp >> 15;
        this.um = (1 << (m.DB - 15)) - 1;
        this.mt2 = 2 * m.t;
    }
    // xR mod m
    convert(x) {
        var r = nbi();
        x.abs().dlShiftTo(this.m.t, r);
        r.divRemTo(this.m, null, r);
        if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
            this.m.subTo(r, r);
        return r;
    }
    // x/R mod m
    revert(x) {
        var r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }
    // x = x/R mod m (HAC 14.32)
    reduce(x) {
        while (x.t <= this.mt2) // pad x so am has enough room later
            x[x.t++] = 0;
        for (var i = 0; i < this.m.t; ++i) {
            // faster way of calculating u0 = x[i]*mp mod DV
            var j = x[i] & 0x7fff;
            var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
            // use am to combine the multiply-shift-add into one call
            j = i + this.m.t;
            x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
            // propagate carry
            while (x[j] >= x.DV) {
                x[j] -= x.DV;
                x[++j]++;
            }
        }
        x.clamp();
        x.drShiftTo(this.m.t, x);
        if (x.compareTo(this.m) >= 0)
            x.subTo(this.m, x);
    }
    // r = "x^2/R mod m"; x != r
    sqrTo(x, r) {
        x.squareTo(r);
        this.reduce(r);
    }
    // r = "xy/R mod m"; x,y != r
    mulTo(x, y, r) {
        x.multiplyTo(y, r);
        this.reduce(r);
    }
}
// x & y
function op_and(x, y) { return x & y; }
// x | y
function op_or(x, y) { return x | y; }
// x ^ y
function op_xor(x, y) { return x ^ y; }
// x & ~y
function op_andnot(x, y) { return x & ~y; }
// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
    if (x == 0)
        return -1;
    var r = 0;
    if ((x & 0xffff) == 0) {
        x >>= 16;
        r += 16;
    }
    if ((x & 0xff) == 0) {
        x >>= 8;
        r += 8;
    }
    if ((x & 0xf) == 0) {
        x >>= 4;
        r += 4;
    }
    if ((x & 3) == 0) {
        x >>= 2;
        r += 2;
    }
    if ((x & 1) == 0)
        ++r;
    return r;
}
// return number of 1 bits in x
function cbit(x) {
    var r = 0;
    while (x != 0) {
        x &= x - 1;
        ++r;
    }
    return r;
}
class NullExp {
    convert(x) { return x; }
    revert(x) { return x; }
    mulTo(x, y, r) { x.multiplyTo(y, r); }
    sqrTo(x, r) { x.squareTo(r); }
}
class Barrett {
    constructor(m) {
        this.m = m;
        // setup Barrett
        this.r2 = nbi();
        this.q3 = nbi();
        BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
        this.mu = this.r2.divide(m);
        this.m = m;
    }
    convert(x) {
        if (x.s < 0 || x.t > 2 * this.m.t)
            return x.mod(this.m);
        else if (x.compareTo(this.m) < 0)
            return x;
        else {
            var r = nbi();
            x.copyTo(r);
            this.reduce(r);
            return r;
        }
    }
    revert(x) {
        return x;
    }
    // x = x mod m (HAC 14.42)
    reduce(x) {
        x.drShiftTo(this.m.t - 1, this.r2);
        if (x.t > this.m.t + 1) {
            x.t = this.m.t + 1;
            x.clamp();
        }
        this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
        this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
        while (x.compareTo(this.r2) < 0)
            x.dAddOffset(1, this.m.t + 1);
        x.subTo(this.r2, x);
        while (x.compareTo(this.m) >= 0)
            x.subTo(this.m, x);
    }
    // r = x^2 mod m; x != r
    sqrTo(x, r) {
        x.squareTo(r);
        this.reduce(r);
    }
    // r = x*y mod m; x,y != r
    mulTo(x, y, r) {
        x.multiplyTo(y, r);
        this.reduce(r);
    }
}
var lowprimes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997
];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Copyright (C) Paul Johnston 2000.
 * See http://pajhome.org.uk/site/legal.html for details.
 *
 * Modified by Tom Wu (tjw@cs.stanford.edu) for the
 * SRP JavaScript implementation.
 */
// function sha1Factory() {
/*
 * Convert a 32-bit number to a hex string with ms-byte first
 */
const hex_chr = "0123456789abcdef";
function hex$1(num) {
    var str = "";
    for (var j = 7; j >= 0; j--)
        str += hex_chr.charAt((num >> (j * 4)) & 0x0F);
    return str;
}
/*
 * Convert a string to a sequence of 16-word blocks, stored as an array.
 * Append padding bits and the length, as described in the SHA1 standard.
 */
function str2blks_SHA1(str) {
    var nblk = ((str.length + 8) >> 6) + 1;
    var blks = new Array(nblk * 16);
    for (var i = 0; i < nblk * 16; i++)
        blks[i] = 0;
    for (i = 0; i < str.length; i++)
        blks[i >> 2] |= str.charCodeAt(i) << (24 - (i % 4) * 8);
    blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
    blks[nblk * 16 - 1] = str.length * 8;
    return blks;
}
/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}
/*
 * Bitwise rotate a 32-bit number to the left
 */
function rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
}
/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function ft(t, b, c, d) {
    if (t < 20)
        return (b & c) | ((~b) & d);
    if (t < 40)
        return b ^ c ^ d;
    if (t < 60)
        return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d;
}
/*
 * Determine the appropriate additive constant for the current iteration
 */
function kt(t) {
    return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 : (t < 60) ? -1894007588 : -899497514;
}
/*
 * Take a string and return the hex representation of its SHA-1.
 */
function calcSHA1(str) {
    return calcSHA1Blks(str2blks_SHA1(str));
}
function calcSHA1Blks(x) {
    var s = calcSHA1Raw(x);
    return hex$1(s[0]) + hex$1(s[1]) + hex$1(s[2]) + hex$1(s[3]) + hex$1(s[4]);
}
function calcSHA1Raw(x) {
    var w = new Array(80);
    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;
    var e = -1009589776;
    for (var i = 0; i < x.length; i += 16) {
        var olda = a;
        var oldb = b;
        var oldc = c;
        var oldd = d;
        var olde = e;
        for (var j = 0; j < 80; j++) {
            var t;
            if (j < 16)
                w[j] = x[i + j];
            else
                w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            t = add(add(rol(a, 5), ft(j, b, c, d)), add(add(e, w[j]), kt(j)));
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        }
        a = add(a, olda);
        b = add(b, oldb);
        c = add(c, oldc);
        d = add(d, oldd);
        e = add(e, olde);
    }
    return new Array(a, b, c, d, e);
}

//export interface BitArray extends Array<number> { }
class BitArray extends Array {
    /**
     * Array slices in units of bits.
     * @param {bitArray} a The array to slice.
     * @param {Number} bstart The offset to the start of the slice, in bits.
     * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
     * slice until the end of the array.
     * @return {bitArray} The requested slice.
     */
    static bitSlice(a, bstart, bend) {
        a = this._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1);
        return (bend === undefined) ? a : this.clamp(a, bend - bstart);
    }
    /**
     * Extract a number packed into a bit array.
     * @param {bitArray} a The array to slice.
     * @param {Number} bstart The offset to the start of the slice, in bits.
     * @param {Number} length The length of the number to extract.
     * @return {Number} The requested slice.
     */
    static extract(a, bstart, blength) {
        // FIXME: this Math.floor is not necessary at all, but for some reason
        // seems to suppress a bug in the Chromium JIT.
        var x, sh = Math.floor((-bstart - blength) & 31);
        if ((bstart + blength - 1 ^ bstart) & -32) {
            // it crosses a boundary
            x = (a[bstart / 32 | 0] << (32 - sh)) ^ (a[bstart / 32 + 1 | 0] >>> sh);
        }
        else {
            // within a single word
            x = a[bstart / 32 | 0] >>> sh;
        }
        return x & ((1 << blength) - 1);
    }
    /**
     * Concatenate two bit arrays.
     * @param {bitArray} a1 The first array.
     * @param {bitArray} a2 The second array.
     * @return {bitArray} The concatenation of a1 and a2.
     */
    static concat(a1, a2) {
        if (a1.length === 0 || a2.length === 0) {
            return a1.concat(a2);
        }
        var last = a1[a1.length - 1], shift = this.getPartial(last);
        if (shift === 32) {
            return a1.concat(a2);
        }
        else {
            return this._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1));
        }
    }
    /**
     * Find the length of an array of bits.
     * @param {bitArray} a The array.
     * @return {Number} The length of a, in bits.
     */
    static bitLength(a) {
        var l = a.length, x;
        if (l === 0) {
            return 0;
        }
        x = a[l - 1];
        return (l - 1) * 32 + this.getPartial(x);
    }
    /**
     * Truncate an array.
     * @param {bitArray} a The array.
     * @param {Number} len The length to truncate to, in bits.
     * @return {bitArray} A new array, truncated to len bits.
     */
    static clamp(a, len) {
        if (a.length * 32 < len) {
            return a;
        }
        a = a.slice(0, Math.ceil(len / 32));
        var l = a.length;
        len = len & 31;
        if (l > 0 && len) {
            a[l - 1] = this.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
        }
        return a;
    }
    /**
     * Make a partial word for a bit array.
     * @param {Number} len The number of bits in the word.
     * @param {Number} x The bits.
     * @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
     * @return {Number} The partial word.
     */
    static partial(len, x, _end) {
        if (len === 32) {
            return x;
        }
        return (_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
    }
    /**
     * Get the number of bits used by a partial word.
     * @param {Number} x The partial word.
     * @return {Number} The number of bits used by the partial word.
     */
    static getPartial(x) {
        return Math.round(x / 0x10000000000) || 32;
    }
    /**
     * Compare two arrays for equality in a predictable amount of time.
     * @param {bitArray} a The first array.
     * @param {bitArray} b The second array.
     * @return {boolean} true if a == b; false otherwise.
     */
    static equal(a, b) {
        if (this.bitLength(a) !== this.bitLength(b)) {
            return false;
        }
        var x = 0, i;
        for (i = 0; i < a.length; i++) {
            x |= a[i] ^ b[i];
        }
        return (x === 0);
    }
    /** Shift an array right.
     * @param {bitArray} a The array to shift.
     * @param {Number} shift The number of bits to shift.
     * @param {Number} [carry=0] A byte to carry in
     * @param {bitArray} [out=[]] An array to prepend to the output.
     * @private
     */
    static _shiftRight(a, shift, carry, out) {
        var i, last2 = 0, shift2;
        if (out === undefined) {
            out = [];
        }
        for (; shift >= 32; shift -= 32) {
            out.push(carry);
            carry = 0;
        }
        if (shift === 0) {
            return out.concat(a);
        }
        for (i = 0; i < a.length; i++) {
            out.push(carry | a[i] >>> shift);
            carry = a[i] << (32 - shift);
        }
        last2 = a.length ? a[a.length - 1] : 0;
        shift2 = this.getPartial(last2);
        out.push(this.partial(shift + shift2 & 31, ((shift + shift2 > 32) ? carry : out.pop()), 1));
        return out;
    }
    /** xor a block of 4 words together.
     * @private
     */
    static _xor4(x, y) {
        return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
    }
    /** byteswap a word array inplace.
     * (does not handle partial words)
     * @param {sjcl.bitArray} a word array
     * @return {sjcl.bitArray} byteswapped array
     */
    static byteswapM(a) {
        var i, v, m = 0xff00;
        for (i = 0; i < a.length; ++i) {
            v = a[i];
            a[i] = (v >>> 24) | ((v >>> 8) & m) | ((v & m) << 8) | (v << 24);
        }
        return a;
    }
}

/** @constructor Ciphertext is corrupt. */
class corrupt {
    constructor(message) {
        this.message = message;
    }
    toString() { return `CORRUPT: ${this.message}`; }
}
/** @constructor Invalid parameter. */
class invalid {
    constructor(message) {
        this.message = message;
    }
    toString() { return `INVALID: ${this.message}`; }
}
/** @constructor Bug or missing feature in SJCL. @constructor */
class bug {
    constructor(message) {
        this.message = message;
    }
    toString() { return "BUG: " + this.message; }
}
/** @constructor Something isn't ready. */
class notReady {
    constructor(message) {
        this.message = message;
    }
    toString() { return "NOT READY: " + this.message; }
}

var exception = /*#__PURE__*/Object.freeze({
    __proto__: null,
    bug: bug,
    corrupt: corrupt,
    invalid: invalid,
    notReady: notReady
});

/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
class aes {
    constructor(key) {
        /**
         * The expanded S-box and inverse S-box tables.  These will be computed
         * on the client so that we don't have to send them down the wire.
         *
         * There are two tables, _tables[0] is for encryption and
         * _tables[1] is for decryption.
         *
         * The first 4 sub-tables are the expanded S-box with MixColumns.  The
         * last (_tables[01][4]) is the S-box itself.
         *
         * @private
         */
        this._tables = [[[], [], [], [], []], [[], [], [], [], []]];
        if (!this._tables[0][0][0]) {
            this._precompute();
        }
        var i, j, tmp, encKey, decKey, sbox = this._tables[0][4], decTable = this._tables[1], keyLen = key.length, rcon = 1;
        if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
            throw new invalid("invalid aes key size");
        }
        this._key = [encKey = key.slice(0), decKey = []];
        // schedule encryption keys
        for (i = keyLen; i < 4 * keyLen + 28; i++) {
            tmp = encKey[i - 1];
            // apply sbox
            if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
                tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];
                // shift rows and add rcon
                if (i % keyLen === 0) {
                    tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
                    rcon = rcon << 1 ^ (rcon >> 7) * 283;
                }
            }
            encKey[i] = encKey[i - keyLen] ^ tmp;
        }
        // schedule decryption keys
        for (j = 0; i; j++, i--) {
            tmp = encKey[j & 3 ? i : i - 4];
            if (i <= 4 || j < 4) {
                decKey[j] = tmp;
            }
            else {
                decKey[j] =
                    decTable[0][sbox[tmp >>> 24]] ^
                        decTable[1][sbox[tmp >> 16 & 255]] ^
                        decTable[2][sbox[tmp >> 8 & 255]] ^
                        decTable[3][sbox[tmp & 255]];
            }
        }
    }
    // public
    /* Something like this might appear here eventually
    name: "AES",
    blockSize: 4,
    keySizes: [4,6,8],
    */
    /**
     * Encrypt an array of 4 big-endian words.
     * @param {Array} data The plaintext.
     * @return {Array} The ciphertext.
     */
    encrypt(data) {
        return this._crypt(data, 0);
    }
    /**
     * Decrypt an array of 4 big-endian words.
     * @param {Array} data The ciphertext.
     * @return {Array} The plaintext.
     */
    decrypt(data) {
        return this._crypt(data, 1);
    }
    /**
     * Expand the S-box tables.
     *
     * @private
     */
    _precompute() {
        var encTable = this._tables[0], decTable = this._tables[1], sbox = encTable[4], sboxInv = decTable[4], i, x, xInv, d = [], th = [], x2, x4, x8, s, tEnc, tDec;
        // Compute double and third tables
        for (i = 0; i < 256; i++) {
            th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
        }
        for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
            // Compute sbox
            s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
            s = s >> 8 ^ s & 255 ^ 99;
            sbox[x] = s;
            sboxInv[s] = x;
            // Compute MixColumns
            x8 = d[x4 = d[x2 = d[x]]];
            tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
            tEnc = d[s] * 0x101 ^ s * 0x1010100;
            for (i = 0; i < 4; i++) {
                encTable[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
                decTable[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
            }
        }
        // Compactify.  Considerable speedup on Firefox.
        for (i = 0; i < 5; i++) {
            encTable[i] = encTable[i].slice(0);
            decTable[i] = decTable[i].slice(0);
        }
    }
    /**
     * Encryption and decryption core.
     * @param {Array} input Four words to be encrypted or decrypted.
     * @param dir The direction, 0 for encrypt and 1 for decrypt.
     * @return {Array} The four encrypted or decrypted words.
     * @private
     */
    _crypt(input, dir) {
        if (input.length !== 4) {
            throw new invalid("invalid aes block size");
        }
        var key = this._key[dir], 
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0] ^ key[0], b = input[dir ? 3 : 1] ^ key[1], c = input[2] ^ key[2], d = input[dir ? 1 : 3] ^ key[3], a2, b2, c2, nInnerRounds = key.length / 4 - 2, i, kIndex = 4, out = [0, 0, 0, 0], table = this._tables[dir], 
        // load up the tables
        t0 = table[0], t1 = table[1], t2 = table[2], t3 = table[3], sbox = table[4];
        // Inner rounds.  Cribbed from OpenSSL.
        for (i = 0; i < nInnerRounds; i++) {
            a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[kIndex];
            b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
            c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
            d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
            kIndex += 4;
            a = a2;
            b = b2;
            c = c2;
        }
        // Last round.
        for (i = 0; i < 4; i++) {
            out[dir ? 3 & -i : i] =
                sbox[a >>> 24] << 24 ^
                    sbox[b >> 16 & 255] << 16 ^
                    sbox[c >> 8 & 255] << 8 ^
                    sbox[d & 255] ^
                    key[kIndex++];
            a2 = a;
            a = b;
            b = c;
            c = d;
            d = a2;
        }
        return out;
    }
}

var cipher = /*#__PURE__*/Object.freeze({
    __proto__: null,
    aes: aes
});

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/** @namespace Hexadecimal */
class hex {
    /** Convert from a bitArray to a hex string. */
    static fromBits(arr) {
        var out = "", i;
        for (i = 0; i < arr.length; i++) {
            out += ((arr[i] | 0) + 0xF00000000000).toString(16).substr(4);
        }
        return out.substring(0, BitArray.bitLength(arr) / 4); //.replace(/(.{8})/g, "$1 ");
    }
    /** Convert from a hex string to a bitArray. */
    static toBits(str) {
        var i, out = [], len;
        str = str.replace(/\s|0x/g, "");
        len = str.length;
        str = str + "00000000";
        for (i = 0; i < str.length; i += 8) {
            out.push(parseInt(str.substr(i, 8), 16) ^ 0);
        }
        return BitArray.clamp(out, len * 4);
    }
}
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * UTF-8 strings
 * @namespace
 */
class utf8String {
    /** Convert from a bitArray to a UTF-8 string. */
    static fromBits(arr) {
        var out = "", bl = BitArray.bitLength(arr), i, tmp = 0;
        for (i = 0; i < bl / 8; i++) {
            if ((i & 3) === 0) {
                tmp = arr[i / 4];
            }
            out += String.fromCharCode(tmp >>> 24);
            tmp <<= 8;
        }
        return decodeURIComponent(escape(out));
    }
    /** Convert from a UTF-8 string to a bitArray. */
    static toBits(str) {
        str = unescape(encodeURIComponent(str));
        var out = [], i, tmp = 0;
        for (i = 0; i < str.length; i++) {
            tmp = tmp << 8 | str.charCodeAt(i);
            if ((i & 3) === 3) {
                out.push(tmp);
                tmp = 0;
            }
        }
        if (i & 3) {
            out.push(BitArray.partial(8 * (i & 3), tmp));
        }
        return out;
    }
}
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Base64 encoding/decoding
 * @namespace
 */
class base64 {
    /** Convert from a bitArray to a base64 string. */
    static fromBits(arr, _noEquals, _url) {
        var out = "", i, bits = 0, c = this._chars, ta = 0, bl = BitArray.bitLength(arr);
        if (_url) {
            c = c.substr(0, 62) + '-_';
        }
        for (i = 0; out.length * 6 < bl;) {
            out += c.charAt((ta ^ arr[i] >>> bits) >>> 26);
            if (bits < 6) {
                ta = arr[i] << (6 - bits);
                bits += 26;
                i++;
            }
            else {
                ta <<= 6;
                bits -= 6;
            }
        }
        while ((out.length & 3) && !_noEquals) {
            out += "=";
        }
        return out;
    }
    /** Convert from a base64 string to a bitArray */
    static toBits(str, _url) {
        str = str.replace(/\s|=/g, '');
        var out = [], i, bits = 0, c = this._chars, ta = 0, x;
        if (_url) {
            c = c.substr(0, 62) + '-_';
        }
        for (i = 0; i < str.length; i++) {
            x = c.indexOf(str.charAt(i));
            if (x < 0) {
                throw new invalid("this isn't base64!");
            }
            if (bits > 26) {
                bits -= 26;
                out.push(ta ^ x >>> bits);
                ta = x << (32 - bits);
            }
            else {
                bits += 6;
                ta ^= x << (32 - bits);
            }
        }
        if (bits & 56) {
            out.push(BitArray.partial(bits & 56, ta, 1));
        }
        return out;
    }
}
/** The base64 alphabet.
 * @private
 */
base64._chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
class base64url {
    static fromBits(arr) {
        return base64.fromBits(arr, 1, 1);
    }
    static toBits(str) {
        return base64.toBits(str, 1);
    }
}

var codec = /*#__PURE__*/Object.freeze({
    __proto__: null,
    base64: base64,
    base64url: base64url,
    hex: hex,
    utf8String: utf8String
});

/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 * @class Secure Hash Algorithm, 256 bits.
 */
class sha256 {
    constructor(hash) {
        this._h = [];
        this._buffer = [];
        this._length = 0;
        if (!sha256._key[0]) { //tm: this should be on prototype i.e. static. see GH: '_precompute path:**/sjcl.js' 
            this._precompute();
        }
        if (hash) {
            this._h = hash._h.slice(0);
            this._buffer = hash._buffer.slice(0);
            this._length = hash._length;
        }
        else {
            this.reset();
        }
    }
    /**
     * Hash a string or an array of words.
     * @static
     * @param {bitArray|String} data the data to hash.
     * @return {bitArray} The hash value, an array of 16 big-endian words.
     */
    static hash(data) {
        return (new sha256()).update(data).finalize();
    }
    /**
     * Reset the hash state.
     * @return this
     */
    reset() {
        this._h = sha256._init.slice(0);
        this._buffer = [];
        this._length = 0;
        return this;
    }
    /**
     * Input several words to the hash.
     * @param {bitArray|String} data the data to hash.
     * @return this
     */
    update(data) {
        if (typeof data === "string") {
            data = utf8String.toBits(data);
        }
        var i, b = this._buffer = BitArray.concat(this._buffer, data), ol = this._length, nl = this._length = ol + BitArray.bitLength(data);
        for (i = 512 + ol & -512; i <= nl; i += 512) {
            this._block(b.splice(0, 16));
        }
        return this;
    }
    /**
     * Complete hashing and output the hash value.
     * @return {bitArray} The hash value, an array of 8 big-endian words.
     */
    finalize() {
        var i, b = this._buffer, h = this._h;
        // Round out and push the buffer
        b = BitArray.concat(b, [BitArray.partial(1, 1)]);
        // Round out the buffer to a multiple of 16 words, less the 2 length words.
        for (i = b.length + 2; i & 15; i++) {
            b.push(0);
        }
        // append the length
        b.push(Math.floor(this._length / 0x100000000));
        b.push(this._length | 0);
        while (b.length) {
            this._block(b.splice(0, 16));
        }
        this.reset();
        return h;
    }
    /*
    _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
    */
    /**
     * The SHA-256 hash key, to be precomputed.
     * @private
     */
    //_key: number[] = [];
    /*
    _key:
      [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
    */
    /**
     * Function to precompute _init and _key.
     * @private
     */
    _precompute() {
        var i = 0, prime = 2, factor;
        function frac(x) { return (x - Math.floor(x)) * 0x100000000 | 0; }
        outer: for (; i < 64; prime++) {
            for (factor = 2; factor * factor <= prime; factor++) {
                if (prime % factor === 0) {
                    // not a prime
                    continue outer;
                }
            }
            if (i < 8) {
                sha256._init[i] = frac(Math.pow(prime, 1 / 2));
            }
            sha256._key[i] = frac(Math.pow(prime, 1 / 3));
            i++;
        }
    }
    /**
     * Perform one cycle of SHA-256.
     * @param {bitArray} words one block of words.
     * @private
     */
    _block(words) {
        var i, tmp, a, b, w = words.slice(0), h = this._h, k = sha256._key, h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];
        /* Rationale for placement of |0 :
         * If a value can overflow is original 32 bits by a factor of more than a few
         * million (2^23 ish), there is a possibility that it might overflow the
         * 53-bit mantissa and lose precision.
         *
         * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
         * propagates around the loop, and on the hash state h[].  I don't believe
         * that the clamps on h4 and on h0 are strictly necessary, but it's close
         * (for h4 anyway), and better safe than sorry.
         *
         * The clamps on h[] are necessary for the output to be correct even in the
         * common case and for short inputs.
         */
        for (i = 0; i < 64; i++) {
            // load up the input word for this round
            if (i < 16) {
                tmp = w[i];
            }
            else {
                a = w[(i + 1) & 15];
                b = w[(i + 14) & 15];
                tmp = w[i & 15] = ((a >>> 7 ^ a >>> 18 ^ a >>> 3 ^ a << 25 ^ a << 14) +
                    (b >>> 17 ^ b >>> 19 ^ b >>> 10 ^ b << 15 ^ b << 13) +
                    w[i & 15] + w[(i + 9) & 15]) | 0;
            }
            tmp = (tmp + h7 + (h4 >>> 6 ^ h4 >>> 11 ^ h4 >>> 25 ^ h4 << 26 ^ h4 << 21 ^ h4 << 7) + (h6 ^ h4 & (h5 ^ h6)) + k[i]); // | 0;
            // shift register
            h7 = h6;
            h6 = h5;
            h5 = h4;
            h4 = h3 + tmp | 0;
            h3 = h2;
            h2 = h1;
            h1 = h0;
            h0 = (tmp + ((h1 & h2) ^ (h3 & (h1 ^ h2))) + (h1 >>> 2 ^ h1 >>> 13 ^ h1 >>> 22 ^ h1 << 30 ^ h1 << 19 ^ h1 << 10)) | 0;
        }
        h[0] = h[0] + h0 | 0;
        h[1] = h[1] + h1 | 0;
        h[2] = h[2] + h2 | 0;
        h[3] = h[3] + h3 | 0;
        h[4] = h[4] + h4 | 0;
        h[5] = h[5] + h5 | 0;
        h[6] = h[6] + h6 | 0;
        h[7] = h[7] + h7 | 0;
    }
}
sha256._key = [];
/**
 * The hash's block size, in bits.
 * @constant
 */
sha256.blockSize = 512;
/**
 * The SHA-256 initialization vector, to be precomputed.
 * @private
 */
sha256._init = [];

var hash = /*#__PURE__*/Object.freeze({
    __proto__: null,
    sha256: sha256
});

/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Michael Brooks
 */
/** @constructor
 * @class Random number generator
 * @description
 * <b>Use sjcl.random as a singleton for this class!</b>
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 */
class prng {
    constructor(_defaultParanoia) {
        this._defaultParanoia = _defaultParanoia;
        /* private */
        this._pools = [new sha256()];
        this._poolEntropy = [0];
        this._reseedCount = 0;
        this._robins = {};
        this._eventId = 0;
        this._collectorIds = {};
        this._collectorIdNext = 0;
        this._strength = 0;
        this._poolStrength = 0;
        this._nextReseed = 0;
        this._key = [0, 0, 0, 0, 0, 0, 0, 0];
        this._counter = [0, 0, 0, 0];
        this._cipher = undefined;
        //private _defaultParanoia = defaultParanoia;
        /* event listener stuff */
        this._collectorsStarted = false;
        this._callbacks = { progress: {}, seeded: {} };
        this._callbackI = 0;
        /* constants */
        this._NOT_READY = 0;
        this._READY = 1;
        this._REQUIRES_RESEED = 2;
        this._MAX_WORDS_PER_BURST = 65536;
        this._PARANOIA_LEVELS = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024];
        this._MILLISECONDS_PER_RESEED = 30000;
        this._BITS_PER_RESEED = 80;
        this._eventListener = {};
    }
    /** Generate several random words, and return them in an array.
     * A word consists of 32 bits (4 bytes)
     * @param {Number} nwords The number of words to generate.
     */
    randomWords(nwords, paranoia) {
        var out = [], i, readiness = this.isReady(paranoia), g;
        if (readiness === this._NOT_READY) {
            throw new notReady("generator isn't seeded");
        }
        else if (readiness & this._REQUIRES_RESEED) {
            this._reseedFromPools(!(readiness & this._READY));
        }
        for (i = 0; i < nwords; i += 4) {
            if ((i + 1) % this._MAX_WORDS_PER_BURST === 0) {
                this._gate();
            }
            g = this._gen4words();
            out.push(g[0], g[1], g[2], g[3]);
        }
        this._gate();
        return out.slice(0, nwords);
    }
    setDefaultParanoia(paranoia, allowZeroParanoia) {
        if (paranoia === 0 && allowZeroParanoia !== "Setting paranoia=0 will ruin your security; use it only for testing") {
            throw "Setting paranoia=0 will ruin your security; use it only for testing";
        }
        this._defaultParanoia = paranoia;
    }
    /**
     * Add entropy to the pools.
     * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
     * @param {Number} estimatedEntropy The estimated entropy of data, in bits
     * @param {String} source The source of the entropy, eg "mouse"
     */
    addEntropy(data, estimatedEntropy, source) {
        source = source || "user";
        var id, i, tmp, t = (new Date()).valueOf(), robin = this._robins[source], oldReady = this.isReady(), err = 0, objName;
        id = this._collectorIds[source];
        if (id === undefined) {
            id = this._collectorIds[source] = this._collectorIdNext++;
        }
        if (robin === undefined) {
            robin = this._robins[source] = 0;
        }
        this._robins[source] = (this._robins[source] + 1) % this._pools.length;
        switch (typeof (data)) {
            case "number":
                if (estimatedEntropy === undefined) {
                    estimatedEntropy = 1;
                }
                this._pools[robin].update([id, this._eventId++, 1, estimatedEntropy, t, 1, data | 0]);
                break;
            case "object":
                objName = Object.prototype.toString.call(data);
                if (objName === "[object Uint32Array]") {
                    tmp = [];
                    for (i = 0; i < data.length; i++) {
                        tmp.push(data[i]);
                    }
                    data = tmp;
                }
                else {
                    if (objName !== "[object Array]") {
                        err = 1;
                    }
                    for (i = 0; i < data.length && !err; i++) {
                        if (typeof (data[i]) !== "number") {
                            err = 1;
                        }
                    }
                }
                if (!err) {
                    if (estimatedEntropy === undefined) {
                        /* horrible entropy estimator */
                        estimatedEntropy = 0;
                        for (i = 0; i < data.length; i++) {
                            tmp = data[i];
                            while (tmp > 0) {
                                estimatedEntropy++;
                                tmp = tmp >>> 1;
                            }
                        }
                    }
                    this._pools[robin].update([id, this._eventId++, 2, estimatedEntropy, t, data.length].concat(data));
                }
                break;
            case "string":
                if (estimatedEntropy === undefined) {
                    /* English text has just over 1 bit per character of entropy.
                     * But this might be HTML or something, and have far less
                     * entropy than English...  Oh well, let's just say one bit.
                     */
                    estimatedEntropy = data.length;
                }
                this._pools[robin].update([id, this._eventId++, 3, estimatedEntropy, t, data.length]);
                this._pools[robin].update(data);
                break;
            default:
                err = 1;
        }
        if (err) {
            throw new bug("random: addEntropy only supports number, array of numbers or string");
        }
        /* record the new strength */
        this._poolEntropy[robin] += estimatedEntropy;
        this._poolStrength += estimatedEntropy;
        /* fire off events */
        if (oldReady === this._NOT_READY) {
            if (this.isReady() !== this._NOT_READY) {
                this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
            }
            this._fireEvent("progress", this.getProgress());
        }
    }
    /** Is the generator ready? */
    isReady(paranoia) {
        var entropyRequired = this._PARANOIA_LEVELS[(paranoia !== undefined) ? paranoia : this._defaultParanoia];
        if (this._strength && this._strength >= entropyRequired) {
            return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
                this._REQUIRES_RESEED | this._READY :
                this._READY;
        }
        else {
            return (this._poolStrength >= entropyRequired) ?
                this._REQUIRES_RESEED | this._NOT_READY :
                this._NOT_READY;
        }
    }
    /** Get the generator's progress toward readiness, as a fraction */
    getProgress(paranoia) {
        var entropyRequired = this._PARANOIA_LEVELS[paranoia ? paranoia : this._defaultParanoia];
        if (this._strength >= entropyRequired) {
            return 1.0;
        }
        else {
            return (this._poolStrength > entropyRequired) ?
                1.0 :
                this._poolStrength / entropyRequired;
        }
    }
    /** start the built-in entropy collectors */
    startCollectors() {
        if (this._collectorsStarted) {
            return;
        }
        if (typeof window !== 'undefined') {
            this._eventListener = {
                loadTimeCollector: this._bind(this._loadTimeCollector),
                mouseCollector: this._bind(this._mouseCollector),
                keyboardCollector: this._bind(this._keyboardCollector),
                accelerometerCollector: this._bind(this._accelerometerCollector),
                touchCollector: this._bind(this._touchCollector)
            };
            if (window.addEventListener) {
                window.addEventListener("load", this._eventListener.loadTimeCollector, false);
                window.addEventListener("keypress", this._eventListener.keyboardCollector, false);
            }
            else {
                throw new bug("can't attach event");
            }
        }
        this._collectorsStarted = true;
    }
    /** stop the built-in entropy collectors */
    stopCollectors() {
        if (!this._collectorsStarted) {
            return;
        }
        if (typeof window !== 'undefined') {
            if (window.removeEventListener) {
                window.removeEventListener("load", this._eventListener.loadTimeCollector, false);
                window.removeEventListener("keypress", this._eventListener.keyboardCollector, false);
            }
        }
        this._collectorsStarted = false;
    }
    /* use a cookie to store entropy.
    useCookie(all_cookies) {
        throw new exception.bug("random: useCookie is unimplemented");
    }*/
    /** add an event listener for progress or seeded-ness. */
    addEventListener(name, callback) {
        this._callbacks[name][this._callbackI++] = callback;
    }
    /** remove an event listener for progress or seeded-ness */
    removeEventListener(name, cb) {
        var i, j, cbs = this._callbacks[name], jsTemp = [];
        //TODO: tm: do it in the js way. later
        /* I'm not sure if this is necessary; in C++, iterating over a
         * collection and modifying it at the same time is a no-no.
         */
        for (j in cbs) {
            if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
                jsTemp.push(j);
            }
        }
        for (i = 0; i < jsTemp.length; i++) {
            j = jsTemp[i];
            delete cbs[j];
        }
    }
    _bind(func) {
        var that = this;
        return function () {
            func.apply(that, arguments);
        };
    }
    /** Generate 4 random words, no reseed, no gate.
     * @private
     */
    _gen4words() {
        for (var i = 0; i < 4; i++) {
            this._counter[i] = this._counter[i] + 1 | 0;
            if (this._counter[i]) {
                break;
            }
        }
        return this._cipher?.encrypt(this._counter) || [];
    }
    /** Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
     * @private
     */
    _gate() {
        this._key = this._gen4words().concat(this._gen4words());
        this._cipher = new aes(this._key);
    }
    /** Reseed the generator with the given words
     * @private
     */
    _reseed(seedWords) {
        this._key = sha256.hash(this._key.concat(seedWords));
        this._cipher = new aes(this._key);
        for (var i = 0; i < 4; i++) {
            this._counter[i] = this._counter[i] + 1 | 0;
            if (this._counter[i]) {
                break;
            }
        }
    }
    /** reseed the data from the entropy pools
     * @param full If set, use all the entropy pools in the reseed.
     */
    _reseedFromPools(full) {
        var reseedData = [], strength = 0, i;
        this._nextReseed = reseedData[0] =
            (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
        for (i = 0; i < 16; i++) {
            /* On some browsers, this is cryptographically random.  So we might
             * as well toss it in the pot and stir...
             */
            reseedData.push(Math.random() * 0x100000000 | 0);
        }
        for (i = 0; i < this._pools.length; i++) {
            reseedData = reseedData.concat(this._pools[i].finalize());
            strength += this._poolEntropy[i];
            this._poolEntropy[i] = 0;
            if (!full && (this._reseedCount & (1 << i))) {
                break;
            }
        }
        /* if we used the last pool, push a new one onto the stack */
        if (this._reseedCount >= 1 << this._pools.length) {
            this._pools.push(new sha256());
            this._poolEntropy.push(0);
        }
        /* how strong was this reseed? */
        this._poolStrength -= strength;
        if (strength > this._strength) {
            this._strength = strength;
        }
        this._reseedCount++;
        this._reseed(reseedData);
    }
    _keyboardCollector() {
        this._addCurrentTimeToEntropy(1);
    }
    _mouseCollector(ev) {
        var x, y;
        try {
            x = ev.x || ev.clientX || ev.offsetX || 0;
            y = ev.y || ev.clientY || ev.offsetY || 0;
        }
        catch (err) {
            // Event originated from a secure element. No mouse position available.
            x = 0;
            y = 0;
        }
        if (x != 0 && y != 0) {
            random.addEntropy([x, y], 2, "mouse");
        }
        this._addCurrentTimeToEntropy(0);
    }
    _touchCollector(ev) {
        var touch = ev.touches[0] || ev.changedTouches[0];
        var x = touch.pageX || touch.clientX, y = touch.pageY || touch.clientY;
        random.addEntropy([x, y], 1, "touch");
        this._addCurrentTimeToEntropy(0);
    }
    _loadTimeCollector() {
        this._addCurrentTimeToEntropy(2);
    }
    _addCurrentTimeToEntropy(estimatedEntropy) {
        if (typeof window !== 'undefined' && typeof window.performance?.now === "function") {
            //how much entropy do we want to add here?
            random.addEntropy(window.performance.now(), estimatedEntropy, "loadtime");
        }
        else {
            random.addEntropy((new Date()).valueOf(), estimatedEntropy, "loadtime");
        }
    }
    _accelerometerCollector(ev) {
        var ac = ev.accelerationIncludingGravity?.x || ev.accelerationIncludingGravity?.y || ev.accelerationIncludingGravity?.z;
        if (typeof window !== 'undefined') {
            if (window.orientation) {
                var or = window.orientation;
                if (typeof or === "number") {
                    random.addEntropy(or, 1, "accelerometer");
                }
            }
        }
        if (ac) {
            random.addEntropy(ac, 2, "accelerometer");
        }
        this._addCurrentTimeToEntropy(0);
    }
    _fireEvent(name, arg) {
        var j, cbs = random._callbacks[name], cbsTemp = [];
        /* TODO: there is a race condition between removing collectors and firing them */
        /* I'm not sure if this is necessary; in C++, iterating over a
         * collection and modifying it at the same time is a no-no.
         */
        for (j in cbs) {
            if (cbs.hasOwnProperty(j)) {
                cbsTemp.push(cbs[j]);
            }
        }
        for (j = 0; j < cbsTemp.length; j++) {
            cbsTemp[j](arg);
        }
    }
} //class prng
const random = new prng(6);

var sjcl = /*#__PURE__*/Object.freeze({
    __proto__: null,
    BitArray: BitArray,
    cipher: cipher,
    codec: codec,
    exception: exception,
    hash: hash,
    random: random
});

var index = /*#__PURE__*/Object.freeze({
    __proto__: null,
    BitArray: BitArray,
    cipher: cipher,
    codec: codec,
    default: sjcl,
    exception: exception,
    hash: hash,
    random: random
});

/*
 * Implementation of an SRP client conforming
 * to the SRP protocol 6A (see RFC5054).
 */
class SRPClient {
    /*
     * Construct an SRP object with a username,
     * password, and the bits identifying the
     * group (1024 [default], 1536 or 2048 bits).
     */
    constructor(username, password, group, hashFn) {
        /*
         * SRP group parameters, composed of N (hexadecimal
         * prime value) and g (decimal group generator).
         * See http://tools.ietf.org/html/rfc5054#appendix-A
         */
        this.initVals = {
            1024: {
                N: 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C' +
                    '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4' +
                    '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29' +
                    '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A' +
                    'FD5138FE8376435B9FC61D2FC0EB06E3',
                g: '2'
            },
            1536: {
                N: '9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961' +
                    '4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843' +
                    '80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B' +
                    'E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5' +
                    '6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A' +
                    'F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E' +
                    '8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB',
                g: '2'
            },
            2048: {
                N: 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294' +
                    '3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D' +
                    'CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB' +
                    'D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74' +
                    '7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A' +
                    '436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D' +
                    '5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73' +
                    '03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6' +
                    '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F' +
                    '9E4AFF73',
                g: '2'
            },
            3072: {
                N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                    'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                    '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                    'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                    '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                    '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                    '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                    'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                    '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                    'E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
                g: '5'
            },
            4096: {
                N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                    'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                    '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                    'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                    '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                    '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                    '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                    'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                    '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                    'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
                    '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
                    '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
                    '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
                    'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199' +
                    'FFFFFFFFFFFFFFFF',
                g: '5'
            },
            6144: {
                N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                    'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                    '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                    'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                    '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                    '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                    '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                    'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                    '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                    'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
                    '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
                    '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
                    '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
                    'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
                    '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406' +
                    'AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918' +
                    'DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151' +
                    '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03' +
                    'F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F' +
                    'BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
                    'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B' +
                    'B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632' +
                    '387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E' +
                    '6DCC4024FFFFFFFFFFFFFFFF',
                g: '5'
            },
            8192: {
                N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                    'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                    '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                    'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                    '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                    '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                    '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                    'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                    '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                    'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
                    '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
                    '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
                    '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
                    'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
                    '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406' +
                    'AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918' +
                    'DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151' +
                    '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03' +
                    'F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F' +
                    'BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
                    'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B' +
                    'B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632' +
                    '387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E' +
                    '6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA' +
                    '3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C' +
                    '5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9' +
                    '22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886' +
                    '2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6' +
                    '6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5' +
                    '0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268' +
                    '359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6' +
                    'FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71' +
                    '60C980DD98EDD3DFFFFFFFFFFFFFFFFF',
                g: '19'
            }
        };
        // Verify presence of username.
        if (!username) {
            throw 'Username cannot be empty.';
        }
        // Store username/password.
        this.username = username;
        this.password = password;
        // Initialize hash function
        this.hashFn = hashFn || 'sha-1';
        // Retrieve initialization values.
        var initVal = this.initVals[group || 1024];
        // Set N and g from initialization values.
        this.N = new BigInteger(initVal.N, 16);
        this.g = new BigInteger(initVal.g, 16);
        //this.gBn = new BigInteger(initVal.g, 16);
        // Pre-compute k from N and g.
        this.k = this.kPrecompute();
        // Convenience big integer objects for 1 and 2.
        this.one = new BigInteger("1", 16);
        this.two = new BigInteger("2", 16);
    }
    toHexString(bi) {
        let hex = bi.toString(16);
        if (hex.length % 2 === 1) {
            hex = "0" + hex;
        }
        return hex;
    }
    padLeft(orig, len) {
        if (orig.length > len) {
            return orig;
        }
        const arr = Array(len - orig.length + 1);
        return arr.join("0") + orig;
    }
    bytesToHex(bytes) {
        const self = this;
        const b = bytes.map(function (x) { return self.padLeft(self.toHexString(x), 2); });
        return b.join("");
    }
    hexToBytes(hex) {
        if (hex.length % 2 === 1) {
            throw new Error("hexToBytes can't have a string with an odd number of characters.");
        }
        if (hex.indexOf("0x") === 0) {
            hex = hex.slice(2);
        }
        return hex.match(/../g)?.map(function (x) { return parseInt(x, 16); }) || [];
    }
    stringToBytes(str) {
        let bytes = [];
        for (var i = 0; i < str.length; ++i) {
            bytes.push(str.charCodeAt(i));
        }
        return bytes;
    }
    bytesToString(byteArr) {
        let str = '';
        for (var i = 0; i < byteArr.length; i++) {
            str += String.fromCharCode(byteArr[i]);
        }
        return str;
    }
    /*
     * Calculate k = H(N || g), which is used
     * throughout various SRP calculations.
     */
    kPrecompute() {
        // Convert to hex values.
        const toHash = [
            this.toHexString(this.N),
            this.toHexString(this.g)
        ];
        // Return hash as a BigInteger.
        return this.paddedHash(toHash);
    }
    /*
     * Calculate x = SHA1(s | SHA1(I | ":" | P))
     */
    calculateX(saltHex) {
        // Verify presence of parameters.
        if (!saltHex) {
            throw new Error('Missing parameter.');
        }
        if (!this.username || !this.password) {
            throw new Error('Username and password cannot be empty.');
        }
        const usernameBytes = this.stringToBytes(this.username);
        const passwordBytes = this.hexToBytes(this.password);
        const upBytes = usernameBytes.concat([58]).concat(passwordBytes);
        const upHash = this.hash(this.bytesToString(upBytes));
        const upHashBytes = this.hexToBytes(upHash);
        const saltBytes = this.hexToBytes(saltHex);
        const saltUpBytes = saltBytes.concat(upHashBytes);
        const saltUpHash = this.hash(this.bytesToString(saltUpBytes));
        const xtmp = new BigInteger(saltUpHash, 16);
        if (xtmp.compareTo(this.N) < 0) {
            return xtmp;
        }
        else {
            const one = new BigInteger(1, 16);
            return xtmp.mod(this.N.subtract(one));
        }
    }
    /*
     * Calculate v = g^x % N
     */
    calculateV(salt) {
        // Verify presence of parameters.
        if (!salt) {
            throw 'Missing parameter.';
        }
        // Get X from the salt value.
        const x = this.calculateX(salt);
        // Calculate and return the verifier.
        return this.g.modPow(x, this.N);
    }
    /*
     * Calculate u = SHA1(PAD(A) | PAD(B)), which serves
     * to prevent an attacker who learns a user's verifier
     * from being able to authenticate as that user.
     */
    calculateU(A, B) {
        // Verify presence of parameters.
        if (!A || !B) {
            throw 'Missing parameter(s).';
        }
        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        // Convert A and B to hexadecimal.
        const toHash = [this.toHexString(A), this.toHexString(B)];
        // Return hash as a BigInteger.
        return this.paddedHash(toHash);
    }
    canCalculateA(a) {
        if (!a) {
            throw 'Missing parameter.';
        }
        return Math.ceil(a.bitLength() / 8) >= 256 / 8;
    }
    /*
     * 2.5.4 Calculate the client's public value A = g^a % N,
     * where a is a random number at least 256 bits in length.
     */
    calculateA(a) {
        // Verify presence of parameter.
        if (!a) {
            throw 'Missing parameter.';
        }
        if (!this.canCalculateA(a)) {
            throw 'Client key length is less than 256 bits.';
        }
        // Return A as a BigInteger.
        const A = this.g.modPow(a, this.N);
        if (A.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        return A;
    }
    /*
     * Calculate match M = H(H(N) XOR H(g) | H(username) | s | A | B | K)
     */
    calculateM1(A, B, K, salt) {
        // Verify presence of parameters.
        if (!A || !B || !K || !salt) {
            throw 'Missing parameter(s).';
        }
        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' ||
            B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        const hashN = this.hexHash(this.toHexString(this.N));
        const hashg = this.hexHash(this.toHexString(this.g));
        const hashUsername = this.hash(this.username);
        var xorNg_bytes = [], hashN_bytes = this.hexToBytes(hashN), hashg_bytes = this.hexToBytes(hashg);
        for (var i = 0; i < hashN_bytes.length; i++) {
            xorNg_bytes[i] = hashN_bytes[i] ^ hashg_bytes[i];
        }
        var xorNg = this.bytesToHex(xorNg_bytes);
        var aHex = this.toHexString(A);
        var bHex = this.toHexString(B);
        var toHash = [xorNg, hashUsername, salt, aHex, bHex, K];
        var toHash_str = '';
        for (var j = 0; j < toHash.length; j++) {
            toHash_str += toHash[j];
        }
        return new BigInteger(this.hexHash(toHash_str), 16);
    }
    /*
     * Calculate match M = H(H(N) XOR H(g) | H(username) | s | A | B | K) and return as hex string
     */
    calculateM(A, B, K, salt) {
        // Verify presence of parameters.
        if (!A || !B || !K || !salt) {
            throw 'Missing parameter(s).';
        }
        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        const hashN = this.hexHash(this.toHexString(this.N));
        const hashg = this.hexHash(this.toHexString(this.g));
        const hashUsername = this.hash(this.username);
        var xorNg_bytes = [], hashN_bytes = this.hexToBytes(hashN), hashg_bytes = this.hexToBytes(hashg);
        for (var i = 0; i < hashN_bytes.length; i++) {
            xorNg_bytes[i] = hashN_bytes[i] ^ hashg_bytes[i];
        }
        var xorNg = this.bytesToHex(xorNg_bytes);
        var aHex = this.toHexString(A);
        var bHex = this.toHexString(B);
        var toHash = [xorNg, hashUsername, salt, aHex, bHex, K];
        var toHash_str = '';
        for (var j = 0; j < toHash.length; j++) {
            toHash_str += toHash[j];
        }
        return this.hexHash(toHash_str);
    }
    /*
     * Calculate match M = H(A, B, K) or M = H(A, M, K)
     */
    calculateM2(A, B_or_M, K) {
        // Verify presence of parameters.
        if (!A || !B_or_M || !K) {
            throw 'Missing parameter(s).';
        }
        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B_or_M.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        const aHex = this.toHexString(A);
        const bHex = this.toHexString(B_or_M);
        const toHash = [aHex, bHex, K];
        let toHash_str = '';
        for (var j = 0; j < toHash.length; j++) {
            toHash_str += toHash[j];
        }
        return new BigInteger(this.hexHash(toHash_str), 16);
    }
    /*
     * Calculate the client's premaster secret
     * S = (B - (k * g^x)) ^ (a + (u * x)) % N
     */
    calculateS(B, salt, uu, aa) {
        // Verify presence of parameters.
        if (!B || !salt || !uu || !aa) {
            throw 'Missing parameters.';
        }
        // Verify value of B.
        if (B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        // Calculate X from the salt.
        const x = this.calculateX(salt);
        // Calculate bx = g^x % N
        const bx = this.g.modPow(x, this.N);
        // Calculate ((B + N * k) - k * bx) % N
        const btmp = B.add(this.N.multiply(this.k)).subtract(bx.multiply(this.k)).mod(this.N);
        // Finish calculation of the premaster secret.
        return btmp.modPow(x.multiply(uu).add(aa), this.N);
    }
    calculateK(S) {
        return this.hexHash(this.toHexString(S));
    }
    /*
     * Helper functions for random number
     * generation and format conversion.
     */
    /* Generate a random big integer */
    srpRandom() {
        const words = sjcl.random.randomWords(8, 0);
        const hex = sjcl.codec.hex.fromBits(words);
        // Verify random number large enough.
        if (hex.length != 64) {
            throw 'Invalid random number size.';
        }
        let rv = new BigInteger(hex, 16);
        if (rv.compareTo(this.N) >= 0) {
            rv = rv.mod(this.N.subtract(this.one)); // tm: rv = a.mod(this.N.subtract(this.one)); where a is undefined
        }
        if (rv.compareTo(this.two) < 0) {
            rv = this.two;
        }
        return rv;
    }
    /* Return a random hexadecimal salt */
    randomHexSalt() {
        const words = sjcl.random.randomWords(8, 0);
        const hex = sjcl.codec.hex.fromBits(words);
        return hex;
    }
    /*
     * Helper functions for hasing/padding.
     */
    /*
     * SHA1 hashing function with padding: input
     * is prefixed with 0 to meet N hex width.
     */
    paddedHash(array) {
        const nlen = 2 * ((this.toHexString(this.N).length * 4 + 7) >> 3);
        let toHash = '';
        for (var i = 0; i < array.length; i++) {
            toHash += this.nZeros(nlen - array[i].length) + array[i];
        }
        const hash = new BigInteger(this.hexHash(toHash), 16);
        return hash.mod(this.N);
    }
    /*
     * Generic hashing function.
     */
    hash(str) {
        switch (this.hashFn.toLowerCase()) {
            case 'sha-256': {
                const s = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str));
                return this.nZeros(64 - s.length) + s;
            }
            case 'sha-1':
            default: {
                return calcSHA1(str);
            }
        }
    }
    /*
     * Hexadecimal hashing function.
     */
    hexHash(str) {
        switch (this.hashFn.toLowerCase()) {
            case 'sha-256': {
                const s = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sjcl.codec.hex.toBits(str)));
                return this.nZeros(64 - s.length) + s;
            }
            case 'sha-1':
            default: {
                return this.hash(this.pack(str));
            }
        }
    }
    /*
     * Hex to string conversion.
     */
    pack(hex) {
        // To prevent null byte termination bug
        if (hex.length % 2 != 0) {
            hex = '0' + hex;
        }
        let i = 0;
        let ascii = '';
        while (i < hex.length / 2) {
            ascii = ascii + String.fromCharCode(parseInt(hex.substr(i * 2, 2), 16));
            i++;
        }
        return ascii;
    }
    /* Return a string with N zeros. */
    nZeros(n) {
        if (n < 1) {
            return '';
        }
        const t = this.nZeros(n >> 1);
        return ((n & 1) == 0) ? t + t : t + t + '0';
    }
    /*
     * Server-side SRP functions. These should not
     * be used on the client except for debugging.
     */
    /* Calculate the server's public value B. */
    calculateB(b, v) {
        // Verify presence of parameters.
        if (!b || !v) {
            throw 'Missing parameters.';
        }
        const bb = this.g.modPow(b, this.N);
        const B = bb.add(v.multiply(this.k)).mod(this.N);
        return B;
    }
    /* Calculate the server's premaster secret */
    calculateServerS(A, v, u, B) {
        // Verify presence of parameters.
        if (!A || !v || !u || !B) {
            throw 'Missing parameters.';
        }
        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }
        return v.modPow(u, this.N).multiply(A).mod(this.N).modPow(B, this.N);
    }
} //class SRPClient

function createDeferredPromise() {
    const rv = {};
    rv.promise = new Promise((_resolve, _reject) => {
        rv.resolve = _resolve;
        rv.reject = _reject;
    });
    return rv;
}
function ajax(method, url, data) {
    const promise = new Promise(function (resolve, reject) {
        const xhr = new XMLHttpRequest();
        xhr.open(method, url, true);
        xhr.responseType = "json";
        xhr.setRequestHeader("Accept", "application/json");
        xhr.onreadystatechange =
            function onreadystatechange() {
                if (this.readyState === XMLHttpRequest.DONE) {
                    if (this.status === 200) {
                        let data;
                        if (this.responseType === '' && typeof this.responseText === "string")
                            data = JSON.parse(this.responseText);
                        else
                            data = this.response;
                        resolve(data);
                    }
                    else {
                        reject(this);
                    }
                }
            };
        if (method.toLowerCase() === "post" && data) {
            var urlEncodedData = "";
            var urlEncodedDataPairs = [];
            var name;
            for (name in data) {
                urlEncodedDataPairs.push(`${encodeURIComponent(name)}=${encodeURIComponent(data[name])}`);
            }
            urlEncodedData = urlEncodedDataPairs.join('&').replace(/%20/g, '+');
            xhr.send(urlEncodedData);
        }
        else {
            xhr.send();
        }
    });
    return promise;
}
class FixedQueue {
    constructor(maxSize) {
        this.m_items = [];
        this.m_items = [];
        this.m_maxSize = maxSize;
    }
    trimHead() {
        if (this.m_items.length > this.m_maxSize) {
            this.m_items.splice(0, this.m_items.length - this.m_maxSize);
        }
    }
    trimTail() {
        if (this.m_items.length > this.m_maxSize) {
            this.m_items.splice(this.m_maxSize, this.m_items.length - this.m_maxSize);
        }
    }
    push(...args) {
        this.m_items.push(...args);
        this.trimHead();
    }
    splice(start, deleteCount) {
        const result = this.m_items.splice(start, deleteCount);
        this.trimTail();
        return result;
    }
    unshift(...args) {
        const result = this.m_items.unshift(...args);
        this.trimTail();
        return result;
    }
    get length() {
        return this.m_items.length;
    }
    get items() {
        return this.m_items;
    }
}

/**
* Loads configuration parameters from configuration server and saves it in session storage.
*/
const SESSIONSTORAGE_CONNECTION_STR_KEY = "websdk"; // sessionStorage connection string
const SESSIONSTORAGE_SESSION_ID_KEY = "websdk.sessionId"; // sessionStorage session ID
class Configurator {
    constructor() {
        this.session = {
            port: 0,
            host: "127.0.0.1",
            secure: true,
            srpClient: null,
        };
        try {
            const storageStr = sessionStorage.getItem(SESSIONSTORAGE_CONNECTION_STR_KEY);
            const sessionData = storageStr && JSON.parse(storageStr);
            if (sessionData) {
                this.session = sessionData;
            }
        }
        catch (error) {
        }
    }
    async ensureLoaded() {
        try {
            if (this.session.port && this.session.host && this.session.srpClient) {
                return {};
            }
            const response = await ajax('get', 'https://127.0.0.1:52181/get_connection');
            if (this.parseHostReply(response?.endpoint)) {
                return {};
            }
        }
        catch (error) {
        }
        return { error: 'Cannot load configuration' };
    }
    parseHostReply(connectionString) {
        const sd = getSRPSessionData(connectionString);
        if (!sd) {
            return false;
        }
        this.session = sd;
        sessionStorage.setItem(SESSIONSTORAGE_CONNECTION_STR_KEY, JSON.stringify(sd));
        return true;
        function getSRPSessionData(connectionString) {
            const co = parseConnectionString(connectionString);
            if (!co) {
                return;
            }
            const sd = {
                host: co.hostname,
                port: parseInt(co.web_sdk_port || ''),
                secure: co.web_sdk_secure === "true",
                srpClient: {
                    p1: co.web_sdk_username,
                    p2: co.web_sdk_password,
                    salt: co.web_sdk_salt,
                },
            };
            if (sd.port && sd.host && sd.srpClient?.p1 && sd.srpClient.p2 && sd.srpClient.salt) {
                return sd;
            }
            function parseConnectionString(str) {
                traceSdk(`Configurator: DpHost string: "${str}"`);
                if (str) {
                    const [_host, rest] = str.split('?');
                    const params = (`hostname=127.0.0.1&${rest}`.split('&') || []);
                    return Object.fromEntries(params.map((param) => param.split('=')));
                }
            }
        }
    }
    getDpHostConnectionUrl() {
        const { port, host, secure } = this.session;
        if (!port || !host) {
            throw new Error('No connection url');
        }
        const newUrl = `${secure ? 'https' : 'http'}://${host}:${port.toString()}`;
        return `${newUrl}/connect`;
    }
    getDpAgentConnectionUrl({ dpAgentChannelId, M1 = 'no.M1' }) {
        const { port, host, secure } = this.session;
        if (!port || !host || !this.session.srpClient) {
            throw new Error('No port,host,srpClient');
        }
        const newUrl = `${secure ? 'https' : 'http'}://${host}:${port.toString()}`;
        let sessionId = this.sessionId;
        if (!sessionId) {
            this.sessionId = sessionId = index.codec.hex.fromBits(index.random.randomWords(2, 0));
        }
        let connectionUrl = `${newUrl.replace('http', 'ws')}/${dpAgentChannelId}?username=${this.session.srpClient.p1}&M1=${M1}`;
        connectionUrl += `&sessionId=${this.sessionId}`;
        connectionUrl += `&version=${envSdk.version.toString()}`;
        return connectionUrl;
    }
    get sessionId() {
        return sessionStorage.getItem(SESSIONSTORAGE_SESSION_ID_KEY);
    }
    set sessionId(value) {
        if (!value) {
            sessionStorage.removeItem(SESSIONSTORAGE_SESSION_ID_KEY);
        }
        else {
            sessionStorage.setItem(SESSIONSTORAGE_SESSION_ID_KEY, value);
        }
    }
}
const configurator = new Configurator();

var WebSdkAESVersion = 1;
var WebSdkAESDataType = {
    Binary: 1,
    UnicodeString: 2,
    UTF8String: 3
};
function utf8ToBase64(str) {
    const binstr = utf8ToBinaryString(str);
    return btoa(binstr);
}
function base64ToUtf8(b64) {
    const binstr = atob(b64);
    return binaryStringToUtf8(binstr);
}
function utf8ToBinaryString(str) {
    const escstr = encodeURIComponent(str);
    return escstr.replace(/%([0-9A-F]{2})/g, (_m, p1) => String.fromCharCode(parseInt(p1, 16)));
}
function binaryStringToUtf8(binstr) {
    const escstr = binstr.replace(/(.)/g, function (_m, p1) {
        let code = p1.charCodeAt(0).toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return `%${code}`;
    });
    return decodeURIComponent(escstr);
}
function xor(key, data) {
    const strArr = Array.prototype.map.call(data, (x) => x);
    return strArr.map((char, idx) => String.fromCharCode(char.charCodeAt(0) ^ keyCharAt(key, idx))).join('');
    function keyCharAt(key, i) {
        return key.charCodeAt(Math.floor(i % key.length));
    }
}
function getHdr(buf) {
    const dv = new DataView(buf);
    return {
        version: dv.getUint8(0),
        type: dv.getUint8(1),
        length: dv.getUint32(2, true),
        offset: dv.getUint16(6, true),
    };
}
function setHdr(buf, type) {
    const dv = new DataView(buf);
    dv.setUint8(0, WebSdkAESVersion); // set version
    dv.setUint8(1, type); // set type
    dv.setUint32(2, buf.byteLength - 8, true); // set length
    dv.setUint16(6, 8, true); // set offset
}
function ab2str(buf) {
    return new Promise(function (resolve, reject) {
        const blob = new Blob([new Uint8Array(buf)]);
        const fileReader = new FileReader();
        fileReader.onload = function (event) {
            return resolve(event.target?.result);
        };
        fileReader.onerror = function (event) {
            return reject(event.target?.error);
        };
        fileReader.readAsText(blob, 'utf-16');
    });
}
function str2ab(str) {
    const buf = new ArrayBuffer(str.length * 2 + 8); // 2 bytes for each char
    setHdr(buf, WebSdkAESDataType.UnicodeString); // unicode string
    const bufView = new Uint16Array(buf, 8);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
function binary2ab(bin) {
    const buf = new ArrayBuffer(bin.length + 8);
    setHdr(buf, WebSdkAESDataType.Binary); // binary string
    const bufSrc = new Uint8Array(bin);
    const bufDest = new Uint8Array(buf, 8);
    bufDest.set(bufSrc);
    return buf;
}
/////////////////////////////////////////////////////////////////////////////
// AES encryption wrappers
// So far we will use AES-CBC 256bit encryption with 128bit IV vector.
// You can use crypto.generateKey or crypto.importKey,
// but since I'm always either going to share, store, or receive a key
// I don't see the point of using 'generateKey' directly
function generateKey(rawKey) {
    const usages = ['encrypt', 'decrypt'];
    const extractable = false;
    return globalThis.crypto.subtle.importKey('raw', rawKey, { name: 'AES-CBC' }, extractable, usages);
}
function AESEncryption(key, M1, data) {
    const iv = new Uint8Array(hexToArray(M1).buffer, 0, 16);
    let buff;
    if (typeof data === 'string')
        buff = str2ab(data);
    else
        buff = binary2ab(data);
    return encryptAES(buff, key, iv);
    function encryptAES(data, key, iv) {
        return generateKey(key).then(function (key) {
            return encrypt(data, key, iv);
        });
        function encrypt(data, key, iv) {
            return globalThis.crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, data); // a public value that should be generated for changes each time
        }
    }
}
function AESDecryption(key, M1, data) {
    const iv = new Uint8Array(hexToArray(M1).buffer, 0, 16);
    return decryptAES(data, key, iv).then(function aa(data) {
        const hdr = getHdr(data);
        if (hdr.version !== WebSdkAESVersion) {
            throw new Error("Invalid data version!");
        }
        switch (hdr.type) {
            case WebSdkAESDataType.Binary: {
                return promisefy(data.slice(hdr.offset));
            }
            case WebSdkAESDataType.UnicodeString: {
                return ab2str(data.slice(hdr.offset));
            }
            default: {
                throw new Error("Invalid data type!");
            }
        }
        //return ab2str(data);
    });
    function decryptAES(data, key, iv) {
        return generateKey(key).then(function (key) {
            return decrypt(data, key, iv);
        });
        function decrypt(data, key, iv) {
            return globalThis.crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, data); // a public value that should be generated for changes each time
        }
    }
}
/////////////////////////////////////////////////////////////////////////////
function encode(key, M1, data) {
    if (!key || !M1) {
        throw new Error("Invalid key|M1");
    }
    switch (envSdk.version) {
        case WebSdkEncryptionSupport.AESEncryption: {
            return AESEncryption(key, M1, data);
        }
        case WebSdkEncryptionSupport.Encryption: {
            return promisefy(utf8ToBase64(xor(M1, data)));
        }
        case WebSdkEncryptionSupport.Encoding: {
            return promisefy(utf8ToBase64(data));
        }
        default: {
            return promisefy(data);
        }
    }
}
function decode(key, M1, data) {
    if (!key || !M1) {
        throw new Error("Invalid key|M1");
    }
    switch (envSdk.version) {
        case WebSdkEncryptionSupport.AESEncryption: {
            return AESDecryption(key, M1, data);
        }
        case WebSdkEncryptionSupport.Encryption: {
            return promisefy(xor(M1, base64ToUtf8(data)));
        }
        case WebSdkEncryptionSupport.Encoding: {
            return promisefy(base64ToUtf8(data));
        }
        default: {
            return promisefy(data);
        }
    }
}
function hexToArray(hex) {
    if (hex.length % 2 === 1) {
        throw new Error("hexToBytes can't have a string with an odd number of characters.");
    }
    if (hex.indexOf("0x") === 0) {
        hex = hex.slice(2);
    }
    return new Uint8Array((hex.match(/../g) || []).map((x) => parseInt(x, 16)));
}
function promisefy(data) {
    return new Promise(function (resolve, reject) {
        setTimeout(function () {
            resolve(data);
        });
    });
}
function hexToBytes(hex) {
    return hexToArray(hex);
}

class WebChannelClientImpl {
    constructor(dpAgentChannelId) {
        this.wsThreshold = 10240; // max number of buffered bytes (10k)
        this.wsQueueInterval = 1000; // interval to process message queue and send data over web-socket if buffer size is less then the threshold
        this.wsQueueLimit = 100; // maximum queue size, when reaching this limit the oldest messages will be removed from the queue.
        this.wsReconnectInterval = 5000;
        this.queue = new FixedQueue(this.wsQueueLimit);
        this.queueInterval = null;
        this.reconnectTimer = null;
        this.webSocket = null;
        this.sessionKey = null;
        this.onConnectionFailed = null;
        this.onConnectionSucceed = null;
        this.onDataReceivedBin = null;
        this.onDataReceivedTxt = null;
        this.reportError = (error) => {
            const msg = (error instanceof Error ? error.message : error.toString()) || 'tm.error.connect';
            console.error(msg);
        };
        traceSdk(`wccImpl.constructor({version: ${envSdk.version}, dpAgentClientId: "${dpAgentChannelId}"})`);
        if (!dpAgentChannelId) {
            throw new Error("clientPath cannot be empty");
        }
        this.dpAgentChannelId = dpAgentChannelId;
    }
    /**
    * Connects to web socket server and setups all event listeners
    */
    wsconnect(url) {
        traceSdk(`wccImpl.wsconnect(${url})`);
        const deferredPromise = createDeferredPromise();
        if (this.webSocket && this.webSocket.readyState !== WebSocket.CLOSED) {
            throw new Error("disconnect has not been called");
        }
        this.webSocket = new WebSocket(url);
        this.webSocket.binaryType = 'arraybuffer'; // we need binary type 'arraybuffer' because default type 'blob' is not working
        this.webSocket.onclose = (event) => {
            traceSdk("wccImpl.wsonclose()");
            return this.wsonclose(true);
        };
        this.webSocket.onopen = function (event) {
            traceSdk("wccImpl.wsonopen()");
            deferredPromise.resolve();
        };
        this.webSocket.onerror = function (event) {
            traceSdk(`wccImpl.wsonerror(${arguments})`);
            return deferredPromise.reject(new Error("WebSocket connection failed."));
        };
        this.webSocket.onmessage = (event) => this.wsonmessage(event);
        return deferredPromise.promise;
    }
    /**
    * Closes web socket connection and cleans up all event listeners
    */
    wsdisconnect() {
        const self = this;
        const deferredPromise = createDeferredPromise();
        if (!this.webSocket || this.webSocket.readyState !== WebSocket.OPEN) {
            deferredPromise.resolve();
        }
        else {
            this.webSocket.onclose = function (event) {
                self.wsonclose(false);
                deferredPromise.resolve();
            };
            this.webSocket.close();
        }
        return deferredPromise.promise;
    }
    wsonclose(isFailed) {
        traceSdk("wccImpl.wsonclose()");
        if (this.webSocket) {
            this.webSocket.onclose = null;
            this.webSocket.onopen = null;
            this.webSocket.onmessage = null;
            this.webSocket.onerror = null;
        }
        this.stopMessageQueueInterval();
        isFailed && this.onConnectionFailed?.();
    }
    wsonmessage(event) {
        decode(this.sessionKey, this.M1, event.data)
            .then((data) => typeof data === 'string' ? this.onDataReceivedTxt?.(data) : this.onDataReceivedBin?.(data));
    }
    sendDataBin(data) {
        encode(this.sessionKey, this.M1, data).then((data) => this.sendData(data)).catch(this.reportError);
    }
    sendDataTxt(data) {
        encode(this.sessionKey, this.M1, data).then((data) => this.sendData(data)).catch(this.reportError);
    }
    sendData(data) {
        if (!this.wssend(data)) {
            this.queue.push(data);
        }
    }
    wssend(data) {
        if (!this.isConnected() || !this.webSocket) {
            return false;
        }
        if (this.webSocket.bufferedAmount >= this.wsThreshold) {
            this.startMessageQueueInterval();
            return false;
        }
        this.webSocket.send(data);
        return true;
    }
    /**
    * True if web socket is ready for transferring data
    */
    isConnected() {
        return !!this.webSocket && this.webSocket.readyState === WebSocket.OPEN;
    }
    stopMessageQueueInterval() {
        this.queueInterval && (clearInterval(this.queueInterval), this.queueInterval = null);
    }
    startMessageQueueInterval() {
        if (!this.queueInterval) {
            this.queueInterval = setInterval(() => this.processMessageQueue(), this.wsQueueInterval);
        }
    }
    /**
    * Sends messages from a queue if any. Initiates secure connection if needed and has not been yet initiated.
    */
    processMessageQueue() {
        if (!this.queue.length) {
            return;
        }
        traceSdk(`wccImpl.processMessageQueue(${this.queue.length})`);
        for (var i = 0; i < this.queue.length;) {
            if (!this.wssend(this.queue.items[i])) {
                break;
            }
            this.queue.splice(i, 1);
        }
        if (this.queue.length === 0) {
            this.stopMessageQueueInterval();
        }
    }
    stopReconnectTimer() {
        this.reconnectTimer && (clearInterval(this.reconnectTimer), this.reconnectTimer = null);
    }
    startReconnectTimer() {
        this.stopReconnectTimer();
        this.reconnectTimer = setInterval(() => this.tryConnectNTimes(1), this.wsReconnectInterval);
    }
    async connect() {
        await this.tryConnectNTimes(3);
    }
    async disconnect() {
        await this.wsdisconnect();
    }
    async generateSessionKey() {
        try {
            const srpData = configurator.session.srpClient;
            if (!srpData?.p1 || !srpData.p2 || !srpData.salt) {
                return { error: "No data available for authentication" };
            }
            const srpClient = new SRPClient(srpData.p1, srpData.p2);
            let a;
            do {
                a = srpClient.srpRandom();
            } while (!srpClient.canCalculateA(a));
            const A = srpClient.calculateA(a);
            const response = await ajax('post', configurator.getDpHostConnectionUrl(), {
                username: srpData.p1,
                A: srpClient.toHexString(A),
                version: envSdk.version.toString(),
            });
            envSdk.version = response.version ?? /*old client*/ Math.min(envSdk.version, WebSdkEncryptionSupport.Encryption);
            const B = new BigInteger(response.B, 16);
            const u = srpClient.calculateU(A, B);
            const S = srpClient.calculateS(B, srpData.salt, u, a);
            const K = srpClient.calculateK(S);
            const M1 = srpClient.calculateM(A, B, K, srpData.salt);
            // we will use SHA256 from K as AES 256bit session key
            this.sessionKey = hexToBytes(index.codec.hex.fromBits(index.hash.sha256.hash(index.codec.hex.toBits(K))));
            this.M1 = M1;
            return { data: M1 };
        }
        catch (error) {
            return { error: (error instanceof Error ? error.message : error.toString()) || 'tm.error.key' };
        }
    }
    /**
    * Sets up connection with parameters from configurator (generates session key and connects to websocket server).
    */
    async setupSecureChannel() {
        traceSdk('wccImpl.setupSecureChannel()');
        const res = await this.generateSessionKey();
        if (res.error) {
            return res;
        }
        try {
            const connectionUrl = configurator.getDpAgentConnectionUrl({ dpAgentChannelId: this.dpAgentChannelId, M1: this.M1 });
            await this.wsconnect(connectionUrl);
            return {};
        }
        catch (error) {
            traceSdk(error);
            return { error: (error instanceof Error ? error.message : error.toString()) || 'tm.error.key' };
        }
    }
    async tryConnectNTimes(nAttempts) {
        traceSdk('wccImpl.connectInternal()');
        this.stopReconnectTimer();
        if (this.isConnected()) {
            return;
        }
        try {
            const res = await configurator.ensureLoaded();
            if (res.error) {
                throw new Error(res.error);
            }
            let attemptsLeft = nAttempts;
            let res2;
            do {
                res2 = await this.setupSecureChannel();
            } while (!!res2.error && --attemptsLeft > 0);
            if (res2.error) {
                throw new Error(res2.error);
            }
            this.onConnectionSucceed?.();
            this.processMessageQueue();
        }
        catch (error) {
            this.onConnectionFailed?.((error instanceof Error ? error.message : error.toString()) || 'tm.error.connect');
        }
    }
} //class WebChannelClientImpl

class WebChannelClient {
    constructor(dpAgentChannelId, options) {
        if (options) {
            traceSdk(options);
            const o = new WebChannelOptions(options);
            envSdk.debug = o.debug;
            envSdk.version = o.version;
        }
        this.impl = new WebChannelClientImpl(dpAgentChannelId);
    }
    connect() {
        return this.impl.connect();
    }
    ;
    disconnect() {
        return this.impl.disconnect();
    }
    ;
    isConnected() {
        return this.impl.isConnected();
    }
    ;
    sendDataBin(data) {
        this.impl.sendDataBin(data);
    }
    ;
    sendDataTxt(data) {
        this.impl.sendDataTxt(data);
    }
    ;
    resetReconnectTimer() {
        this.impl.stopReconnectTimer();
    }
    ;
    get onConnectionFailed() { return this.impl.onConnectionFailed; }
    set onConnectionFailed(v) { this.impl.onConnectionFailed = v; }
    get onConnectionSucceed() { return this.impl.onConnectionSucceed; }
    set onConnectionSucceed(v) { this.impl.onConnectionSucceed = v; }
    get onDataReceivedBin() { return this.impl.onDataReceivedBin; }
    set onDataReceivedBin(v) { this.impl.onDataReceivedBin = v; }
    get onDataReceivedTxt() { return this.impl.onDataReceivedTxt; }
    set onDataReceivedTxt(v) { this.impl.onDataReceivedTxt = v; }
}

export { WebChannelClient, WebChannelClientImpl, WebChannelOptions };
