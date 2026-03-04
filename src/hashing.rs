pub(crate) const HEX_LUT: &[u8; 512] = b"\
000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f\
505152535455565758595a5b5c5d5e5f\
606162636465666768696a6b6c6d6e6f\
707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f\
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

#[inline]
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut buf = Vec::with_capacity(bytes.len() * 2);
    let lut = HEX_LUT.as_ptr();
    for &b in bytes {
        let idx = (b as usize) * 2;
        unsafe {
            buf.push(*lut.add(idx));
            buf.push(*lut.add(idx + 1));
        }
    }
    unsafe { String::from_utf8_unchecked(buf) }
}

fn md5_compress(chunk: &[u8], state: &mut [u32; 4]) {
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut m = [0u32; 16];
    let base = chunk.as_ptr();
    for i in 0..16 {
        m[i] = unsafe {
            u32::from_le(std::ptr::read_unaligned(base.add(i * 4) as *const u32))
        };
    }

    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    for i in 0usize..64 {
        let (f, g): (u32, usize) = match i {
             0..=15 => ((b & c) | (!b & d),         i),
            16..=31 => ((d & b) | (!d & c),         (5 * i + 1) % 16),
            32..=47 => (b ^ c ^ d,                  (3 * i + 5) % 16),
            _       => (c ^ (b | !d),               (7 * i) % 16),
        };
        let t = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]),
        );
        a = t;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

pub fn md5_hex(data: &[u8]) -> String {
    let orig_bits = (data.len() as u64).wrapping_mul(8);
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

    let full_blocks = data.len() / 64;
    for i in 0..full_blocks {
        md5_compress(&data[i * 64..(i + 1) * 64], &mut state);
    }

    let remaining = &data[full_blocks * 64..];
    let mut tail = [0u8; 128];
    tail[..remaining.len()].copy_from_slice(remaining);
    tail[remaining.len()] = 0x80;
    let pad_len = if remaining.len() < 56 { 64 } else { 128 };
    tail[pad_len - 8..pad_len].copy_from_slice(&orig_bits.to_le_bytes());

    for chunk in tail[..pad_len].chunks_exact(64) {
        md5_compress(chunk, &mut state);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&state[0].to_le_bytes());
    digest[4..8].copy_from_slice(&state[1].to_le_bytes());
    digest[8..12].copy_from_slice(&state[2].to_le_bytes());
    digest[12..16].copy_from_slice(&state[3].to_le_bytes());
    bytes_to_hex(&digest)
}

fn sha256_compress(chunk: &[u8], h: &mut [u32; 8]) {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut w = [0u32; 64];
    let base = chunk.as_ptr();
    for i in 0..16 {
        w[i] = unsafe {
            u32::from_be(std::ptr::read_unaligned(base.add(i * 4) as *const u32))
        };
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g; g = f; f = e;
        e = d.wrapping_add(t1);
        d = c; c = b; b = a;
        a = t1.wrapping_add(t2);
    }

    let add = [a, b, c, d, e, f, g, hh];
    for i in 0..8 {
        h[i] = h[i].wrapping_add(add[i]);
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let orig_bits = (data.len() as u64).wrapping_mul(8);
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let full_blocks = data.len() / 64;
    for i in 0..full_blocks {
        sha256_compress(&data[i * 64..(i + 1) * 64], &mut h);
    }

    let remaining = &data[full_blocks * 64..];
    let mut tail = [0u8; 128];
    tail[..remaining.len()].copy_from_slice(remaining);
    tail[remaining.len()] = 0x80;
    let pad_len = if remaining.len() < 56 { 64 } else { 128 };
    tail[pad_len - 8..pad_len].copy_from_slice(&orig_bits.to_be_bytes());

    for chunk in tail[..pad_len].chunks_exact(64) {
        sha256_compress(chunk, &mut h);
    }

    let mut digest = [0u8; 32];
    for i in 0..8 {
        digest[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    bytes_to_hex(&digest)
}

pub fn calculate_checksum(data: &[u8]) -> u32 {
    let len = data.len();
    let word_count = len / 2;
    let mut cs: u64 = 0;

    unsafe {
        let ptr = data.as_ptr();
        for i in 0..word_count {
            let w = u16::from_le(std::ptr::read_unaligned(ptr.add(i * 2) as *const u16)) as u64;
            cs = (cs & 0xFFFF_FFFF) + w;
            if cs > 0x1_0000_0000 {
                cs = (cs & 0xFFFF_FFFF) + (cs >> 32);
            }
        }
        if len % 2 != 0 {
            cs += *ptr.add(len - 1) as u64;
        }
    }

    cs = (cs >> 16) + (cs & 0xFFFF);
    cs += cs >> 16;
    (cs & 0xFFFF) as u32 + len as u32
}
