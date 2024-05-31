# Ransomware for Windows

This is a toy ransomware for Windows 10. It encrypts your files in your Documents folder. You need the [Rescuer](https://github.com/SlemimanPzz/Rescuer.git) for decrypting the files. It generates a random AES256 key, encrypts it with the public RSA key hard-coded into it, and stores it on the desktop. It encrypts all .docx, .xlsx, .pdf, .jpeg, .jpg, and .txt files, but it can be easily expanded to include more file types.

> **WARNING: DO NOT RUN THIS ON YOUR MACHINE. USE A VIRTUAL MACHINE (VM) INSTEAD.**

## To Build
- Download [Rust](https://www.rust-lang.org/tools/install)
- Run `cargo build --release` to get the executable. If you're not on a Windows system, add the `--target=x86_64-pc-windows-gnu` flag.
- The `.exe` file will be located in `target/release/Ransomware.exe` or `target/debug/Ransomware.exe` if you didn't use the `--release` flag.

> **DO NOT run `cargo run`, especially on a Windows system, as this will encrypt all your files. Also, the private key corresponding to the public key is provided. You can change it to your own using an RSA Key pair in PKCS#8 format.**

## For Executing
- You need to run it as an administrator.
- You need to deactivate Windows Defender.

# Link to [Rescuer](https://github.com/SlemimanPzz/Rescuer.git)
