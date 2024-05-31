# Ransomware for Windows

This sis a toy ransomware for Windows 10. It encrypts your files in your documents folder. You need the the [Rescuer](https://github.com/SlemimanPzz/Rescuer.git) for decrypting de files. It generates a random AES256 key, and then encrypt it with the public RSA key hard coded into it and stores it on the desktop. It encrypts all docx, xlsx, pdf, jpeg, jpg, txt, it can be expanded to more easily.

> DON'T RUN ON YOUR MACHINE, USE A VM

## To build 

- Download [Rust](https://www.rust-lang.org/tools/install) 
- Do `cargo build --release` get the executable, if you are not on a windows system add the `--target=x86_64-pc-windows-gnu` flag
- The `.exe` will be located in `taget/release/Ransomware.exe` or in `taget/debug/Ransomware.exe` if you didn't use the `--release` flag.

> DO NOT do `cargo run`, especially on a windows system since this will encrypt all your files. Also the private key link to the public key is provided. You can change it to your own using a RSA Key pair in PKCS#8.

## For executing

- You need to run it has an administrator
- You need to deactivate windows defenter