use clap::Parser;
use orion::errors::UnknownCryptoError;
use orion::aead::SecretKey;
use std::io::Write;
use std::io;
use std::fs;
use std::fs::File;
use orion::aead;
use orion::kdf::{self, Password, Salt};

/// And simple CLI based password manager
#[derive(Parser)]
struct Cli{
    /// Initiates the Password Mangager
    #[arg(short,long)]
    init: bool,
}

fn main() {
    let args = Cli::parse();
    if args.init {
        match init(){
            Ok(()) => println!("Initiation was succesfull"),
            Err(error) => {
                println!("Couldnt initialize: {}", error)
            }
        }
    }

}
fn init() -> std::io::Result<()>{
    let password = match get_user_password(){
        Ok(password) => password,
        Err(error) => return Err(std::io::Error::other(error)),
    };

    let data = br#"{"entries":[]}"#;

    let encrypted_data = encrypt(&password, data);

    fs::write("data.enc", encrypted_data).expect("Error while initiating file");
    Ok(())
}

fn store_sault(salt: &Salt) -> std::io::Result<()>{
    let mut file = File::create("salt.bin")?;
    file.write_all(salt.as_ref())?;
    Ok(())
}

fn generate_key(password: &kdf::Password) -> Result<SecretKey, UnknownCryptoError>{
    let salt = Salt::default();
    store_sault(&salt).expect("Couldnt store Salt"); 
    let key = kdf::derive_key(password, &salt, 5, 1<<16, 32);
    key
}

fn get_user_password() -> Result<Password,UnknownCryptoError>{
    println!("Please input MasterPassword!\n(!IMPORTANT! This password cant be restored, if you lose it you lose everthing)");
    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .expect("Error when trying to read password input"); //Password is currently visible when typing
    let password = password.trim_end();
    let password = kdf::Password::from_slice(password.as_bytes());
    password
}

fn encrypt(password: &kdf::Password,data: &[u8]) -> Vec<u8>{
    let key = generate_key(&password).expect("Error while generating key");
    let encrypted_data =aead::seal(&key,data).expect("Erro while trying to encrypting file");
    encrypted_data
}

fn load_key(password: & kdf::Password)  -> Result<SecretKey, UnknownCryptoError> { //used after initlasation
    let salt_bytes = fs::read("salt.bin").expect("Couldnt read salt.bin, check if file exitst");
    let salt = Salt::from_slice(&salt_bytes)?;
    let key = kdf::derive_key(password, &salt, 5, 1<<16, 32);
    key
}