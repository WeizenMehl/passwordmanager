use clap::Parser;
use orion::errors::UnknownCryptoError;
use orion::aead::SecretKey;
use serde::Serialize;
use std::io::Write;
use std::io;
use std::fs;
use std::fs::File;
use orion::aead;
use orion::hash::{digest, Digest};
use orion::kdf::{self, Password, Salt};
use serde_json::{json,Value};
use serde::Deserialize;
use rpassword;
/// And simple CLI based password manager
#[derive(Parser)]
struct Cli{
    /// Initiates the Password Manager
    #[arg(short,long)]
    init: bool,

    /// Add an password and title
    #[arg(short,long)]
    add: bool,

    /// Show specific username
    #[arg(short,long)]
    show: Option<String>,

    #[arg(short,long)]
    titles: bool,

    /// Deletes an entry
    #[arg(short,long)]
    delete: Option<String>,
}

fn main() {
    let args = Cli::parse();
    if args.init {
        match init(){
            Ok(()) => println!("Initiation was successfull"),
            Err(error) => println!("Couldnt initialize: {}", error)
        }

    }
    else if args.add {
        match add(){
            Ok(()) => println!("Added password"),
            Err(error) => println!("Couldnt add password: {}",error)
        }
    }
    else if let Some(titel) = args.show {
        match show(&titel){
            Ok(()) => println!("Showing password was successfull"),
            Err(error) => println!("Couldnt show password: {}", error)
            
        }
    }
    else if args.titles {
        match titles(){
            Ok(()) => println!("Showing all titles was successfull"),
            Err(error) => println!("Couldnt show titles: {}", error)
        }
    }
    else if let Some(titel) = args.delete{
        match delete(&titel){
            Ok(()) => println!("Deleteting entry was successfull"),
            Err(error) => println!("Couldnt delete entry: {}", error)
        }
    }
}
fn init() -> std::io::Result<()>{
    println!("Please input MasterPassword!\n(!IMPORTANT! This password cant be restored, if you lose it you lose everthing)");
    let masterpassword = get_user_password().expect("error while getting user password");
    let password_hash = digest(masterpassword.unprotected_as_bytes()).expect("error while hashing masterpassword");
    store_masterpassword(&password_hash).expect("couldnt store password_hash");

    init_salt()?;
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

#[derive(Deserialize, Serialize)]
struct Entry {
    password: String,
    titel: String,
}

// showes specific password for an given Titel
fn show(titel: &str) -> std::io::Result<()>{
    let masterpassword = get_user_password().expect("error while getting user password");
    if !check_userpassword(&masterpassword){
        println!("Password is incorrect");
        return Ok(())
    }

    let data = fs::read("data.enc")?;
    let decrypted_data: Vec<Entry> = serde_json::from_slice(&decrypt(&masterpassword, &data))?;

    let password =  decrypted_data.iter().find(|x| x.titel == titel).map(|x| x.password.as_str());
    
    if let Some(password) = password {
        println!("Titel: {}, Password {}", titel,password);
    }
    else {
        println!("No entry found for titel: {}",titel);
    } 
    Ok(()) 
}

// shows all titles
fn titles() -> std::io::Result<()>{
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

fn delete(titel: &str) -> std::io::Result<()>{
    let masterpassword = get_user_password().expect("error while getting user password");
    if !check_userpassword(&masterpassword){
        println!("Password is incorrect");
        return Ok(())
    }

    let data = fs::read("data.enc")?;
    let mut decrypted_data: Vec<Entry> = serde_json::from_slice(&decrypt(&masterpassword, &data))?;
    let entry_index = decrypted_data.iter().position(|x|x.titel == titel);

    if let Some(entry_index) = entry_index{
        decrypted_data.remove(entry_index);
        let modified: String = serde_json::to_string(&decrypted_data)?;
        let encrypted_data = encrypt(&masterpassword, &modified.as_bytes());
        fs::write("data.enc", &encrypted_data).expect("Couldnt write to file");
    }
    else{
        println!("No entry found for titel: {}", titel);
    }

    Ok(())
}

fn check_userpassword(password: &kdf::Password) -> bool{
    let stored_hash = fs::read("hash.bin").expect("error while reading stored hash from file");
    let password_hash = digest(password.unprotected_as_bytes()).expect("error while hasing password");

     stored_hash == password_hash.as_ref()
}
fn store_masterpassword(password: &Digest) -> std::io::Result<()> {
    let mut file = File::create("hash.bin")?;
    file.write_all(password.as_ref())?;
    Ok(())
}

fn init_salt() -> std::io::Result<()>{
    let salt = Salt::default();
    let mut file = File::create("salt.bin")?;
    file.write_all(salt.as_ref())?;
    Ok(())
}

fn get_user_password() -> Result<Password,UnknownCryptoError>{
    let masterpassword = rpassword::prompt_password("Input Master Password").unwrap();
    let masterpassword = masterpassword.trim_end();
    let masterpassword = kdf::Password::from_slice(masterpassword.as_bytes());
    masterpassword
}

fn encrypt(password: &kdf::Password,data: &[u8]) -> Vec<u8>{
    let key = load_key(password).expect("couldnt load key");
    let encrypted_data =aead::seal(&key,data).expect("Erro while trying to encrypting file");
    encrypted_data
}

fn decrypt(password: &kdf::Password, data: &[u8]) -> Vec<u8>{
    let key = load_key(password).expect("couldnt load key");
    let decrypted_data = aead::open(&key, data).expect("Error while trying to decrypt data");
    decrypted_data
}

fn load_key(password: & kdf::Password)  -> Result<SecretKey, UnknownCryptoError> { //used after Initialization
    let salt_bytes = fs::read("salt.bin").expect("Couldnt read salt.bin, salt.bin should exist");
    let salt = Salt::from_slice(&salt_bytes)?;
    let key = kdf::derive_key(password, &salt, 3, 1<<15, 32);
    key
}