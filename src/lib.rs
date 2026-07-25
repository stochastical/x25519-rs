use rand::{
    Rng, SeedableRng,
    rngs::{StdRng, SysRng},
};

type FieldElem = [i64; 16];

fn unpack25519(input: &[u8], out: &mut FieldElem) {
    for i in 0..16 {
        out[i] = input[2 * i] as i64 + ((input[2 * i + 1] as i64) << 8);
    }
    out[15] &= 0x7fff;
}

fn carry25519(elem: &mut FieldElem) {
    for i in 0..16 {
        let carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if i < 15 {
            elem[i + 1] += carry;
        } else {
            elem[0] += 38 * carry;
        }
    }
}

fn fadd(a: &FieldElem, b: &FieldElem, out: &mut FieldElem) {
    for i in 0..16 {
        out[i] = a[i] + b[i];
    }
}

fn fsub(a: &FieldElem, b: &FieldElem, out: &mut FieldElem) {
    for i in 0..16 {
        out[i] = a[i] - b[i];
    }
}

fn fmul(a: &FieldElem, b: &FieldElem, out: &mut FieldElem) {
    let mut product = [0; 31];

    for i in 0..16 {
        for j in 0..16 {
            product[i + j] += a[i] * b[j];
        }
    }
    for i in 0..15 {
        product[i] += 38 * product[i + 16];
    }

    for i in 0..16 {
        out[i] = product[i];
    }
    carry25519(out);
    carry25519(out);
}

fn finverse(input: &FieldElem, out: &mut FieldElem) {
    let mut c: FieldElem = *input;
    for i in (0..=253).rev() {
        fmul(&c.clone(), &c.clone(), &mut c);
        if i != 2 && i != 4 {
            fmul(&c.clone(), input, &mut c);
        }
    }
    *out = c;
}

fn swap25519(p: &mut FieldElem, q: &mut FieldElem, bit: i64) {
    let mut t;
    let c = !(bit as i64 - 1);
    for i in 0..16 {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

fn pack25519(input: &FieldElem, out: &mut [u8; 32]) {
    let mut carry;
    let mut m: FieldElem = [0; 16];
    let mut t: FieldElem = [0; 16];
    for i in 0..16 {
        t[i] = input[i];
    }
    carry25519(&mut t);
    carry25519(&mut t);
    carry25519(&mut t);

    for _ in 0..2 {
        m[0] = t[0] - 0xffed;
        for i in 1..15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(&mut t, &mut m, 1 - carry);
    }
    for i in 0..16 {
        out[2 * i] = (t[i] & 0xff) as u8;
        out[2 * i + 1] = (t[i] >> 8) as u8;
    }
}

fn scalarmult(scalar: &[u8; 32], point: &[u8; 32], out: &mut [u8; 32]) {
    let mut _121665: FieldElem = [0; 16];
    [_121665[0], _121665[1]] = [0xDB41, 1];

    let mut clamped = [0; 32];
    let mut bit: i64;
    let mut a: FieldElem = [0; 16];
    let mut b: FieldElem = [0; 16];
    let mut c: FieldElem = [0; 16];
    let mut d: FieldElem = [0; 16];
    let mut e: FieldElem = [0; 16];
    let mut f: FieldElem = [0; 16];
    let mut x: FieldElem = [0; 16];

    for i in 0..32 {
        clamped[i] = scalar[i];
    }
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;
    unpack25519(point, &mut x);

    for i in 0..16 {
        b[i] = x[i];
        (d[i], a[i], c[i]) = (0, 0, 0);
    }
    (a[0], d[0]) = (1, 1);
    for i in (0..=254).rev() {
        bit = ((clamped[i >> 3] >> (i & 7)) & 1) as i64;
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
        fadd(&a, &c, &mut e);
        fsub(&a.clone(), &c, &mut a);
        fadd(&b, &d, &mut c);
        fsub(&b.clone(), &d, &mut b);
        fmul(&e, &e, &mut d);
        fmul(&a, &a, &mut f);
        fmul(&c, &a.clone(), &mut a);
        fmul(&b, &e, &mut c);
        fadd(&a, &c, &mut e);
        fsub(&a.clone(), &c, &mut a);
        fmul(&a, &a, &mut b);
        fsub(&d, &f, &mut c);
        fmul(&c, &_121665, &mut a);
        fadd(&a.clone(), &d, &mut a);
        fmul(&c.clone(), &a, &mut c);
        fmul(&d, &f, &mut a);
        fmul(&b, &x, &mut d);
        fmul(&e, &e, &mut b);
        swap25519(&mut a, &mut b, bit);
        swap25519(&mut c, &mut d, bit);
    }
    finverse(&c.clone(), &mut c);
    fmul(&a.clone(), &c, &mut a);
    pack25519(&a, out);
}

fn scalarmult_base(scalar: &[u8; 32], out: &mut [u8; 32]) {
    let mut _9 = [0; 32];
    _9[0] = 9;
    scalarmult(scalar, &_9, out);
}

fn generate_keypair(pk: &mut [u8; 32], sk: &mut [u8; 32]) {
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    rng.fill_bytes(sk);
    scalarmult_base(sk, pk);
}

fn x25519(pk: &[u8; 32], sk: &[u8; 32], out: &mut [u8; 32]) {
    scalarmult(sk, pk, out);
}
