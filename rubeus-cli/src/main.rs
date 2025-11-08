use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "rubeus")]
#[command(about = "Kerberos exploitation toolkit (Rust port)", long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Calculate Kerberos password hashes
    Hash {
        /// Password to hash
        #[arg(long)]
        password: String,

        /// Username (optional, for salt)
        #[arg(long)]
        user: Option<String>,

        /// Domain (optional, for salt)
        #[arg(long)]
        domain: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    println!(
        r"      ______        _
     (_____ \      | |
      _____) )_   _| |__   ___  _   _ ___
     |  __  /| | | |  _ \ / _ \| | | / __|
     | |  \ \| |_| | |_) |  __/| |_| \__ \
     |_|   |_|\__,_|____/ \___| \__,_|___/

      v0.1.0 (Rust port)
      CTF Lab / Educational Use Only
"
    );

    match cli.command {
        Some(Commands::Hash {
            password,
            user,
            domain,
        }) => {
            println!("\n[*] Action: Calculate Password Hash(es)\n");
            println!("[*] Input password             : {}", password);
            if let Some(u) = user {
                println!("[*] Input username             : {}", u);
            }
            if let Some(d) = domain {
                println!("[*] Input domain               : {}", d);
            }
            println!("\n[!] Cryptography module not yet implemented");
        }
        None => {
            println!("\nUsage: rubeus <COMMAND>");
            println!("\nCommands:");
            println!("  hash        Calculate Kerberos password hashes");
            println!("\nUse 'rubeus <COMMAND> --help' for more information on a command");
        }
    }

    Ok(())
}
