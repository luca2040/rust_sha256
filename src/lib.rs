/// sha256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// as sha256 definition
#[inline(always)]
fn sigma0(num: u32) -> u32 {
    num.rotate_right(7) ^ num.rotate_right(18) ^ (num >> 3)
}

/// as sha256 definition
#[inline(always)]
fn sigma1(num: u32) -> u32 {
    num.rotate_right(17) ^ num.rotate_right(19) ^ (num >> 10)
}

/// as sha256 definition
#[inline(always)]
fn capsigma0(num: u32) -> u32 {
    num.rotate_right(2) ^ num.rotate_right(13) ^ num.rotate_right(22)
}

/// as sha256 definition
#[inline(always)]
fn capsigma1(num: u32) -> u32 {
    num.rotate_right(6) ^ num.rotate_right(11) ^ num.rotate_right(25)
}

/// as sha256 definition
#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// as sha256 definition
#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// returns sha256 hash of the input string
pub fn hash(msg: &str) -> [u8; 32] {
    let mut message = msg.as_bytes().to_vec();

    // pad as sha256 definition

    let bit_len = (message.len() as u64) * 8;
    message.push(0x80);

    let pad = (56usize.wrapping_sub(message.len() % 64)) % 64;
    message.extend(std::iter::repeat(0).take(pad));
    message.extend_from_slice(&bit_len.to_be_bytes());

    // initial hash values as definition

    let mut h0: u32 = 0x6A09E667;
    let mut h1: u32 = 0xBB67AE85;
    let mut h2: u32 = 0x3C6EF372;
    let mut h3: u32 = 0xA54FF53A;
    let mut h5: u32 = 0x9B05688C;
    let mut h4: u32 = 0x510E527F;
    let mut h6: u32 = 0x1F83D9AB;
    let mut h7: u32 = 0x5BE0CD19;

    // compute hash as definition

    for block in message.chunks_exact(64) {
        let mut message_schedule = [0u32; 64];

        for t in 0..16 {
            let i = t * 4;
            message_schedule[t] =
                u32::from_be_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);
        }

        for t in 16..64 {
            message_schedule[t] = sigma1(message_schedule[t - 2])
                .wrapping_add(message_schedule[t - 7])
                .wrapping_add(sigma0(message_schedule[t - 15]))
                .wrapping_add(message_schedule[t - 16]);
        }

        let mut a: u32 = h0;
        let mut b: u32 = h1;
        let mut c: u32 = h2;
        let mut d: u32 = h3;
        let mut e: u32 = h4;
        let mut f: u32 = h5;
        let mut g: u32 = h6;
        let mut h: u32 = h7;

        for t in 0..64 {
            let t1 = h
                .wrapping_add(capsigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(message_schedule[t]);

            let t2 = capsigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    let mut result: [u8; 32] = [0u8; 32];

    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result[20..24].copy_from_slice(&h5.to_be_bytes());
    result[24..28].copy_from_slice(&h6.to_be_bytes());
    result[28..32].copy_from_slice(&h7.to_be_bytes());

    result
}
