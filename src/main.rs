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

    let key = match generate_key(&password){
        Ok(secretkey) => secretkey,
        Err(error) => return Err(std::io::Error::other(error)),
    };
    File::create("data.bin")?;

    encrypt_file(&key, "data.bin");
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
        .expect("Error when trying to read password input");
    let password = password.trim_end();
    let password = kdf::Password::from_slice(password.as_bytes());
    password
}

fn encrypt_file(key: &SecretKey,filename: &str){
    let data = fs::read(filename).expect("Error while trying to open file");
    aead::seal(key,&data).expect("Erro while trying to encrypt file");
}