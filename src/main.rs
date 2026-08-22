use clap::Parser;
use orion::errors::UnknownCryptoError;
use orion::aead::SecretKey;
use std::io::Write;
use std::io;
use std::fs;
use std::fs::File;
use orion::aead;
use orion::hash::{digest, Digest};
use orion::kdf::{self, Password, Salt};
use serde_json::{json,Value};
use serde::Deserialize;
/// And simple CLI based password manager
#[derive(Parser)]
struct Cli{
    /// Initiates the Password Mangager
    #[arg(short,long)]
    init: bool,

    /// Add an password and title
    #[arg(short,long)]
    add: bool,

    /// Show specific username
    #[arg(short,long)]
    show: Option<String>,

    #[arg(short,long)]
    titels: bool,
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
    else if args.add {
        match add(){
            Ok(()) => println!("Added password"),
            Err(error) => {
                println!("Couldnt add password: {}",error)
            }
        }
    }
    else if let Some(titel) = args.show {
        match show(&titel){
            Ok(()) => println!("Shwowing password was succesfull"),
            Err(error) => {
                println!("Couldnt show password: {}", error)
            }
        }
    }
    else if args.titels {
        match titels(){
            Ok(()) => println!("Shwowing all titels was succesfull"),
            Err(error) => {
                println!("Couldnt show titels: {}", error)
            }
        }
    }
}
fn init() -> std::io::Result<()>{
    println!("Please input MasterPassword!\n(!IMPORTANT! This password cant be restored, if you lose it you lose everthing)");
    let masterpassword = get_user_password().expect("error while getting user password");
    let password_hash = digest(masterpassword.unprotected_as_bytes()).expect("error while hashing masterpassword");
    store_masterpassword(&password_hash).expect("couldnt store password_hash");

    let data = br#"[]"#;

    let encrypted_data = encrypt(&masterpassword, data);

    fs::write("data.enc", encrypted_data).expect("Error while initiating file");
    Ok(())
}

fn add() -> std::io::Result<()>{
    println!("Input your master password");
    let masterpassword = get_user_password().expect("error while getting user password");
    if !check_userpassword(&masterpassword){
        println!("Password is incorrect");
        return Ok(())
    }

    let mut titel = String::new();
    println!("Input the Titel of the service");
    io::stdin()
        .read_line(&mut titel)
        .expect("Couldnt read titel input");
    let titel = titel.trim_end();
    
    let mut password = String::new();
    println!("Input the password for the service");
    io::stdin()
        .read_line(&mut password)
        .expect("Couldnt read password input");
    let password = password.trim_end();

    let data = fs::read("data.enc")?;
    let mut decrypted_data: Value = serde_json::from_slice(&decrypt(&masterpassword, &data))?;


    decrypted_data.as_array_mut().unwrap().push(json!({
        "titel": titel,
        "password": password
    }));
    let modified: Vec<u8> = serde_json::to_vec(&decrypted_data)?;
    let encrypted_data = encrypt(&masterpassword, &modified);
    fs::write("data.enc", &encrypted_data).expect("Couldnt write to file");
    Ok(())
}

#[derive(Deserialize)]
struct Entry {
    password: String,
    titel: String,
}

// showes specific password for an given Titel
fn show(titel: &str) -> std::io::Result<()>{
    println!("Input Master Password");
    let masterpassword = get_user_password().expect("error while getting user password");
    if !check_userpassword(&masterpassword){
        println!("Password is incorrect");
        return Ok(())
    }

    let data = fs::read("data.enc")?;
    let decrypted_data: Vec<Entry> = serde_json::from_slice(&decrypt(&masterpassword, &data))?;

    let password =  decrypted_data.iter().find(|x| x.titel == titel).map(|x| x.password.as_str());
    
    if let Some(x) = password {
        println!("Titel: {}, Password {}", titel,x);
    }
    else {
        println!("No entry found for titel: {}",titel);
    } 
    Ok(()) 
}

// shows all titels
fn titels() -> std::io::Result<()>{
    println!("Input Master Password");
    let masterpassword = get_user_password().expect("error while getting user password");
    if !check_userpassword(&masterpassword){
        println!("Password is incorrect");
        return Ok(())
    }

    let data = fs::read("data.enc")?;
    let decrypted_data: Vec<Entry> = serde_json::from_slice(&decrypt(&masterpassword, &data))?;

    for entry in decrypted_data.iter(){
        println!("Titel: {}", entry.titel);
    }
    Ok(())
}

fn check_userpassword(password: &kdf::Password) -> bool{
    let stored_hash = fs::read("hash.bin").expect("error while reading stored hash from file");
    let password_hash = digest(password.unprotected_as_bytes()).expect("error while hasing password");

    if stored_hash == password_hash.as_ref(){
        return true
    }
    else{
        return false
    }
}

fn store_masterpassword(password: &Digest) -> std::io::Result<()> {
    let mut file = File::create("hash.bin")?;
    file.write_all(password.as_ref())?;
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

fn decrypt(password: &kdf::Password, data: &[u8]) -> Vec<u8>{
    let key = load_key(password).expect("Error while loading key");
    let decrypted_data = aead::open(&key, data).expect("Error while trying to decrypt data");
    decrypted_data
}

fn load_key(password: & kdf::Password)  -> Result<SecretKey, UnknownCryptoError> { //used after initlasation
    let salt_bytes = fs::read("salt.bin").expect("Couldnt read salt.bin, check if file exitst");
    let salt = Salt::from_slice(&salt_bytes)?;
    let key = kdf::derive_key(password, &salt, 5, 1<<16, 32);
    key
}