use std::time::Instant;

// ################ some shit to print things ################

trait Printable {
    fn print(&self);
}

impl<const N: usize> Printable for [u8; N] {
    fn print(&self) {
        let hex_groups = self
            .chunks(2)
            .map(|pair| match pair.len() {
                1 => format!("{:02X}", pair[0]),
                _ => format!("{:02X} {:02X}", pair[0], pair[1]),
            })
            .collect::<Vec<String>>();

        for group in hex_groups.chunks(8) {
            println!("{}", group.join(" ").trim_end());
        }
    }
}

fn print_data<T: Printable>(data: &T) {
    data.print();
}

// ###########################################################

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

/// convert a string to a bytearray
fn string_to_byte_array(s: String) -> Vec<u8> {
    s.as_bytes().to_vec()
}

/// pad message as sha256 definition
fn pad_message(msg: &mut Vec<u8>) {
    let message_bytes_num = msg.len() * 8;

    msg.push(0x80);
    while (msg.len() * 8 + 64) % 512 != 0 {
        msg.push(0x00);
    }

    msg.append(&mut message_bytes_num.to_be_bytes().to_vec());
}

/// divide padded message into blocks
fn get_blocks(p_msg: Vec<u8>) -> Vec<[u8; 64]> {
    let msg_len = p_msg.len();
    let num_chunks = msg_len / 64;

    let mut blocks = Vec::with_capacity(num_chunks);

    for i in 0..num_chunks {
        let start = i * 64;
        let end = start + 64;

        let chunk: &[u8] = &p_msg[start..end];

        let mut array = [0u8; 64];
        array.copy_from_slice(chunk);

        blocks.push(array);
    }

    blocks
}

/// convert bytes to integer
fn int_from_bytes(bytes: &[u8; 4]) -> u32 {
    (bytes[0] as u32) << 24 | (bytes[1] as u32) << 16 | (bytes[2] as u32) << 8 | bytes[3] as u32
}

/// as sha256 definition
fn sigma0(num: u32) -> u32 {
    num.rotate_right(7) ^ num.rotate_right(18) ^ (num >> 3)
}

/// as sha256 definition
fn sigma1(num: u32) -> u32 {
    num.rotate_right(17) ^ num.rotate_right(19) ^ (num >> 10)
}

/// as sha256 definition
fn capsigma0(num: u32) -> u32 {
    num.rotate_right(2) ^ num.rotate_right(13) ^ num.rotate_right(22)
}

/// as sha256 definition
fn capsigma1(num: u32) -> u32 {
    num.rotate_right(6) ^ num.rotate_right(11) ^ num.rotate_right(25)
}

/// as sha256 definition
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// as sha256 definition
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// returns sha256 hash of the input string
fn hash(msg: &str) -> [u8; 32] {
    let mut message = string_to_byte_array(msg.to_string());

    pad_message(&mut message);

    let blocks = get_blocks(message);

    // initial hash values
    let mut h0: u32 = 0x6A09E667;
    let mut h1: u32 = 0xBB67AE85;
    let mut h2: u32 = 0x3C6EF372;
    let mut h3: u32 = 0xA54FF53A;
    let mut h5: u32 = 0x9B05688C;
    let mut h4: u32 = 0x510E527F;
    let mut h6: u32 = 0x1F83D9AB;
    let mut h7: u32 = 0x5BE0CD19;

    for block in blocks {
        let mut message_schedule: Vec<[u8; 4]> = Vec::with_capacity(64);

        for t in 0..64 {
            if t <= 15 {
                let mut word = [0u8; 4];
                word.copy_from_slice(&block[t * 4..(t * 4) + 4]);
                message_schedule.push(word);
            } else {
                let term1: u64 =
                    sigma1(int_from_bytes(message_schedule.get(t - 2).unwrap())) as u64;
                let term2: u64 = int_from_bytes(message_schedule.get(t - 7).unwrap()) as u64;
                let term3: u64 =
                    sigma0(int_from_bytes(message_schedule.get(t - 15).unwrap())) as u64;
                let term4: u64 = int_from_bytes(message_schedule.get(t - 16).unwrap()) as u64;

                message_schedule
                    .push((((term1 + term2 + term3 + term4) % 0x100000000) as u32).to_be_bytes());
            }
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
            let t1: u32 = ((h as u64
                + capsigma1(e) as u64
                + ch(e, f, g) as u64
                + K[t] as u64
                + int_from_bytes(&message_schedule[t]) as u64)
                % 0x100000000) as u32;

            let t2: u32 = ((capsigma0(a) as u64 + maj(a, b, c) as u64) % 0x100000000) as u32;

            h = g;
            g = f;
            f = e;
            e = ((d as u64 + t1 as u64) % 0x100000000) as u32;
            d = c;
            c = b;
            b = a;
            a = ((t1 as u64 + t2 as u64) % 0x100000000) as u32;
        }

        h0 = ((h0 as u64 + a as u64) % 0x100000000) as u32;
        h1 = ((h1 as u64 + b as u64) % 0x100000000) as u32;
        h2 = ((h2 as u64 + c as u64) % 0x100000000) as u32;
        h3 = ((h3 as u64 + d as u64) % 0x100000000) as u32;
        h4 = ((h4 as u64 + e as u64) % 0x100000000) as u32;
        h5 = ((h5 as u64 + f as u64) % 0x100000000) as u32;
        h6 = ((h6 as u64 + g as u64) % 0x100000000) as u32;
        h7 = ((h7 as u64 + h as u64) % 0x100000000) as u32;
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

fn main() {
    let input = "Hello";

    hash(input);

    let start = Instant::now();
    let hash_result = hash(input);
    let elapsed = start.elapsed();

    println!("Result:");
    print_data(&hash_result);

    let seconds = elapsed.as_secs_f64();

    println!("Rust time: {}", seconds);
}
