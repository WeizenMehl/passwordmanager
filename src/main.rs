use clap::Parser;
mod lib;

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
        match lib::init(){
            Ok(()) => println!("Initiation was successfull"),
            Err(error) => println!("Couldnt initialize: {}", error)
        }

    }
    else if args.add {
        match lib::add(){
            Ok(()) => println!("Added password"),
            Err(error) => println!("Couldpasswordmanager::lib::*;nt add password: {}",error)
        }
    }
    else if let Some(titel) = args.show {
        match lib::show(&titel){
            Ok(()) => println!("Showing password was successfull"),
            Err(error) => println!("Couldnt show password: {}", error)
            
        }
    }
    else if args.titles {
        match lib::titles(){
            Ok(()) => println!("Showing all titles was successfull"),
            Err(error) => println!("Couldnt show titles: {}", error)
        }
    }
    else if let Some(titel) = args.delete{
        match lib::delete(&titel){
            Ok(()) => println!("Deleteting entry was successfull"),
            Err(error) => println!("Couldnt delete entry: {}", error)
        }
    }
}