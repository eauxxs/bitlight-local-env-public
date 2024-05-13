// src/main.rs
mod api_commands;
mod blockchain_commands;
use dotenv::dotenv;
use structopt::StructOpt;

#[derive(StructOpt)]
pub struct Addr {
    addr: String,
}
#[derive(StructOpt)]
enum Command {
    Mint(blockchain_commands::Mint),
    Get(api_commands::Get),
    Send(Addr),
}

#[derive(StructOpt)]
struct Cli {
    #[structopt(subcommand)]
    cmd: Option<Command>,
}

fn main() {
    dotenv().ok(); // load environment variables from .env file
    let args = Cli::from_args();
    match args.cmd {
        Some(Command::Mint(mint)) => {
            blockchain_commands::mint(mint);
        }
        Some(Command::Get(get)) => {
            api_commands::get(get);
        }
        Some(Command::Send(addr)) => {
            blockchain_commands::send(addr);
        }
        None => {
            println!("No command provided");
        }
    }
}
