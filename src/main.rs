use std::{
    convert::TryInto,
    env::{self},
    fs::File,
    io::{self, Read},
    path::Path,
    time::Instant,
};

// Constants for SHA-512
const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

// Initial hash values for SHA-512
const INITIAL_HASH: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

// SHA-512 block size in bytes
const BLOCK_SIZE: usize = 128;

// Buffer size for file reads - 16kb (small is better :D)
const BUFFER_SIZE: usize = 16 * 1024; // 1024 bytes

// Error type
#[derive(Debug)]
pub enum Sha512Error {
    IoError(io::Error),
    InvalidInputError(String),
    SecurityError(String),
    OverflowError,
}

impl From<io::Error> for Sha512Error {
    fn from(error: io::Error) -> Self {
        Sha512Error::IoError(error)
    }
}

impl std::fmt::Display for Sha512Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sha512Error::IoError(err) => write!(f, "IO error {err}"),
            Sha512Error::InvalidInputError(msg) => write!(f, "Input error: {msg}"),
            Sha512Error::SecurityError(msg) => write!(f, "Security error: {msg}"),
            Sha512Error::OverflowError => write!(f, "Overflow error in length calculation"),
        }
    }
}

impl std::error::Error for Sha512Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Sha512Error::IoError(err) => Some(err),
            _ => None,
        }
    }
}

// Result type for SHA-512 operations
type Sha512Result<T> = Result<T, Sha512Error>;

// SHA-512 digest
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Sha512Digest([u8; 64]); // 64-byte hash result

impl Sha512Digest {
    // Convert the digest to hex string
    pub fn to_hex_string(&self) -> String {
        use std::fmt::Write;
        self.0.iter().fold(String::new(), |mut output, b| {
            let _ = write!(output, "{:02x}", b);
            output
        })
    }

    // COmpare with another hex string (contant time)
    pub fn verify_hex(&self, hex_string: &str) -> bool {
        if hex_string.len() != 128 {
            return false;
        }

        let hex_bytes = hex_string.as_bytes();
        let mut result = true;

        for i in 0..64 {
            let expected_hex = format!("{:02x}", self.0[i]);
            let expected_bytes = expected_hex.as_bytes();

            // Contant-time comparison to prevent timing attacks
            let byte1_match = (expected_bytes[0] == hex_bytes[i * 2]) as u8;
            let byte2_match = (expected_bytes[1] == hex_bytes[i * 2 + 1]) as u8;

            result &= byte1_match == 1 && byte2_match == 1;
        }

        result
    }

    // Get row bytes
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

// SHA-512 hasher structure
pub struct Sha512 {
    h: [u64; 8],
    block: [u8; BLOCK_SIZE],
    block_len: usize,
    total_len: u128,
}

impl Sha512 {
    // Create a new SHA-512 hasher
    pub fn new() -> Self {
        Self {
            h: INITIAL_HASH,
            block: [0; BLOCK_SIZE],
            block_len: 0,
            total_len: 0,
        }
    }

    // Reset the hasher to initial state
    pub fn reset(&mut self) {
        self.h = INITIAL_HASH;
        self.block = [0; BLOCK_SIZE];
        self.block_len = 0;
        self.total_len = 0;
    }

    // Update the hasher with input data
    pub fn update(&mut self, data: &[u8]) -> Sha512Result<()> {
        // Prevent integer overflow in length calculation
        let new_len = self
            .total_len
            .checked_add(data.len() as u128)
            .ok_or(Sha512Error::OverflowError)?;

        self.total_len = new_len;

        let mut data_index = 0;

        // Process any remaining data from previous data
        if self.block_len > 0 {
            let available_space = BLOCK_SIZE - self.block_len;
            let copy_len = std::cmp::min(available_space, data.len());

            self.block[self.block_len..self.block_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.block_len += copy_len;
            data_index += copy_len;

            if self.block_len == BLOCK_SIZE {
                self.process_block();
                self.block_len = 0;
            }
        }

        // Process full blocks directly from input
        while data_index + BLOCK_SIZE <= data.len() {
            self.block
                .copy_from_slice(&data[data_index..data_index + BLOCK_SIZE]);

            data_index += BLOCK_SIZE;
            self.process_block();
        }

        // Store remaining bytes for next update
        let remaining = data.len() - data_index;
        if remaining > 0 {
            self.block[0..remaining].copy_from_slice(&data[data_index..]);
            self.block_len = remaining;
        }

        Ok(())
    }

    // Process a complete block
    fn process_block(&mut self) {
        let mut w = [0_u64; 80];

        // Prepare message schedule big-edian
        // for (i, chunk) in w.iter_mut().enumerate().take(16) {
        //     let bytes = &self.block[i + 8..(i + 1) * 8];
        //     *chunk = u64::from_be_bytes(bytes.try_into().unwrap());
        // }

        for i in 0..16 {
            let i8 = i * 8;
            let bytes = &self.block[i8..i8 + 8];
            w[i] = u64::from_be_bytes(bytes.try_into().unwrap());
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);

            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // initialze working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // Compression function main loop
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) & (!e & g);

            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) & a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Update hash values
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[0].wrapping_add(b);
        self.h[2] = self.h[0].wrapping_add(c);
        self.h[3] = self.h[0].wrapping_add(d);
        self.h[4] = self.h[0].wrapping_add(e);
        self.h[5] = self.h[0].wrapping_add(f);
        self.h[6] = self.h[0].wrapping_add(g);
        self.h[7] = self.h[0].wrapping_add(h);
    }

    // Finalize the hash computaion and return the digest
    pub fn finalize(mut self) -> Sha512Digest {
        // Add padding
        let bit_len = self.total_len * 8;
        self.update(&[0x80]).expect("Update should not fail"); // Append a single 1 bit

        // Pad with zeros until the last bytes
        if self.block_len > 112 {
            // not enough space for length
            while self.block_len < BLOCK_SIZE {
                self.block[self.block_len] = 0;
                self.block_len += 1;
            }

            self.process_block();
            self.block_len = 0;
        }

        // Pad remaining space
        while self.block_len < 112 {
            self.block[self.block_len] = 0;
            self.block_len += 1;
        }

        // Append length of message as 128 big-endian
        for i in 0..16 {
            self.block[112 + i] = ((bit_len >> (120 - i * 8)) & 0xff) as u8;
        }
        self.process_block();

        // Produce the final hash value (big-endian)
        let mut result = [0; 64];
        for i in 0..8 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&self.h[i].to_be_bytes());
        }

        Sha512Digest(result)
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

// Hash a file with SHA-512
pub fn hash_file(path: &Path) -> Sha512Result<Sha512Digest> {
    // Check if file exists and is readable
    if !path.exists() {
        return Err(Sha512Error::InvalidInputError(format!(
            "file not found:  {}",
            path.display()
        )));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha512::new();

    // Use a buffer size
    let mut buffer = [0; BUFFER_SIZE];

    loop {
        match file.read(&mut buffer) {
            Ok(0) => break, // end of file
            Ok(bytes_read) => hasher.update(&buffer[..bytes_read])?,
            Err(e) => return Err(Sha512Error::IoError(e)),
        }
    }

    Ok(hasher.finalize())
}

// Hash a string with SHA-512
pub fn hash_string(input: &str) -> Sha512Result<Sha512Digest> {
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes())?;
    Ok(hasher.finalize())
}

// Hash bytes with SHA-512
pub fn hash_bytes(input: &[u8]) -> Sha512Result<Sha512Digest> {
    let mut hasher = Sha512::new();
    hasher.update(input)?;
    Ok(hasher.finalize())
}

// Verify if a hash matched expected value
pub fn verify_hash(path: &Path, expected_hash: &str) -> Sha512Result<bool> {
    let digest = hash_file(path)?;
    Ok(digest.verify_hex(expected_hash))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Print usage information if no arguments are provided
    if args.len() < 2 {
        println!("SHA-512 Hasher");
        println!("Usage:");
        println!("   {} -s \"string to hash\"", args[0]);
        println!("   {} -f filename", args[1]);
        println!("   {} -v hash filename (verify)", args[2]);
        return Ok(());
    }

    match args[1].as_str() {
        // Hash a string
        "-s" => {
            if args.len() < 3 {
                return Err(Box::new(Sha512Error::InvalidInputError(
                    "no string provided".to_string(),
                )));
            }
            let start = Instant::now();
            let hash = hash_string(&args[2])?;
            let duration = start.elapsed();
            println!("{}", hash.to_hex_string());
            eprintln!("time elapsed: {:?}", duration);
        }
        "-f" => {
            if args.len() < 3 {
                return Err(Box::new(Sha512Error::InvalidInputError(
                    "no filename provided".to_string(),
                )));
            }
            let path = Path::new(&args[2]);
            let start = Instant::now();
            let hash = hash_file(path)?;
            let duration = start.elapsed();
            println!("{}", hash.to_hex_string());
            eprintln!("time elapsed: {:?}", duration);
        }
        "-v" => {
            if args.len() < 4 {
                return Err(Box::new(Sha512Error::InvalidInputError(
                    "Usage: -v hash filename".to_string(),
                )));
            }
            let expected_hash = args[2].to_lowercase();
            let path = Path::new(&args[3]);

            if expected_hash.len() != 128 || !expected_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Box::new(Sha512Error::InvalidInputError(
                    "invalid hash format".to_string(),
                )));
            }

            let start = Instant::now();
            let matches = verify_hash(path, &expected_hash)?;
            let duration = start.elapsed();

            if matches {
                println!("{}: OK", path.display());
            } else {
                println!("{}: FAILED", path.display());
                println!("Expected: {}", expected_hash);

                let hash = hash_file(path)?;
                println!("Computed: {}", hash.to_hex_string());
            }
            eprintln!("time elapsed: {:?}", duration);
        }

        // unknown option
        _ => {
            return Err(Box::new(Sha512Error::InvalidInputError(format!(
                "unknown option: {}",
                args[1]
            ))));
        }
    }

    Ok(())
}

// Unit tests for SHA-512 implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        // SHA-512 of empty string
        let expected = "831a57f223fb2b63678d55759750a87ee47983e80726dc0312db23f148edd4cc24ad65a8da795a8972083b59f47a8f5dc46d6e04aa8e7bd1e3ecf5cd48abe125";
        let hash = hash_string("").unwrap();
        assert_eq!(hash.to_hex_string(), expected);
    }

    #[test]
    fn test_abcd() {
        // SHA-512 of string "abcd"
        let expected = "0a2d6f09e92a80bc86649eb5d76bac63dd2d12749e001e7a5b4c939941cd8629f5cab9451103e1948ee8c8ec422f067ba060a2b404c30f07c2d5be94acc3e910";
        let hash = hash_string("abcd").unwrap();
        assert_eq!(hash.to_hex_string(), expected);
    }

    #[test]
    fn test_longer_text() {
        // SHA-512 of longer random string "l;iq23rjp9ijasdflkjhq23r9opiuhw"
        let expected = "66650c7b86da7e46ff1937c2e87bb08c1f79b56170937fca51a8d36221698c89adc76ac7a8e77835627d2c61eec9932351e553927ff7b1960a35d4f367e9c7d5";
        let hash = hash_string("l;iq23rjp9ijasdflkjhq23r9opiuhw").unwrap();
        assert_eq!(hash.to_hex_string(), expected);
    }

    #[test]
    fn test_verify_correct_hash() {
        let temp_file = "test_file_correct.txt";
        std::fs::write(temp_file, b"test content").unwrap();

        let hash = hash_file(Path::new(temp_file)).unwrap();
        let hex_hash = hash.to_hex_string();

        let result = verify_hash(Path::new(temp_file), &hex_hash).unwrap();
        assert!(result);

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_verify_incorrect_hash() {
        let temp_file = "test_file_incorrect.txt";
        std::fs::write(temp_file, b"test content").unwrap();
        let wrong_hash = "000000000000000000000000000000000000000000000";

        let result = verify_hash(Path::new(temp_file), wrong_hash).unwrap();
        assert!(!result);

        std::fs::remove_file(temp_file).unwrap();
    }

    #[test]
    fn test_digest_equality() {
        let hash1 = hash_string("test").unwrap();
        let hash2 = hash_string("test").unwrap();
        let hash3 = hash_string("different").unwrap();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_reset() {
        let mut hasher = Sha512::new();
        hasher.update(b"test").unwrap();
        hasher.reset();

        #[allow(clippy::let_unit_value)]
        #[allow(unused_variables)]
        let hash1 = hasher.update(b"abc").unwrap();
        let hash1 = hasher.finalize();

        let hash2 = hash_string("abc").unwrap();

        assert_eq!(hash1, hash2);
    }
}
