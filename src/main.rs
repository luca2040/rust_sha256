// ################ some shit to print things ################

trait Printable {
    fn print(&self);
}

impl Printable for String {
    fn print(&self) {
        println!("{}", self);
    }
}

impl Printable for Vec<u8> {
    fn print(&self) {
        let hex_groups = self
            .chunks(2)
            .map(|pair| {
                if pair.len() > 1 {
                    format!("{:02X} {:02X}", pair[0], pair[1])
                } else {
                    format!("{:02X}", pair[0])
                }
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
fn get_blocks(p_msg: Vec<u8>) -> Vec<Vec<u8>> {
    let msg_len = p_msg.len();
    let num_chunks = msg_len / 64;

    let mut blocks = Vec::new();

    for i in 0..num_chunks {
        let start = i * 64;
        let end = start + 64;

        let chunk = &p_msg[start..end];
        blocks.push(chunk.to_vec());
    }

    blocks
}

/// returns sha256 hash of the input string
fn hash(msg: &str) -> &str {
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

    for block in blocks {}

    "still testing"
}

fn main() {
    let input = "Hello";

    let hash_result = hash(input);

    println!("Result: {}", hash_result);
}
