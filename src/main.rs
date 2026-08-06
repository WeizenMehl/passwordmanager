use clap::Parser;
use std::io;
use std::fs::File;

/// And simple CLI based password manager
#[derive(Parser)]
struct Cli{
    /// Initiates the Packages Mangager
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
    println!("Please input MasterPassword!\n(!IMPORTANT! This password cant be reseted if you lose it you lose everthing)");
    let mut password = String::new(); //this will for now serve no purpose but eventually encryption will be implemented
    io::stdin()
        .read_line(&mut password)
        .expect("Error when trying to read password input");
    File::create("data.csv")?;
    Ok(())
}
