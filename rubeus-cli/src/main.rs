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
            use rubeus_core::crypto::{EType, password_hash, compute_salt};

            println!("\n[*] Action: Calculate Password Hash(es)\n");
            println!("[*] Input password             : {}", password);

            // RC4-HMAC doesn't need salt
            match password_hash(EType::Rc4Hmac, &password, "", 4096) {
                Ok(hash) => println!("[*]       rc4_hmac             : {}", hash),
                Err(e) => eprintln!("[!] RC4-HMAC error: {}", e),
            }

            // AES and DES need username and domain for salt
            if let (Some(u), Some(d)) = (user, domain) {
                println!("[*] Input username             : {}", u);
                println!("[*] Input domain               : {}", d);

                let salt = compute_salt(&d, &u);
                println!("[*] Salt                       : {}", salt);

                match password_hash(EType::Aes128CtsHmacSha1, &password, &salt, 4096) {
                    Ok(hash) => println!("[*]       aes128_cts_hmac_sha1 : {}", hash),
                    Err(e) => eprintln!("[!] AES128 error: {}", e),
                }

                match password_hash(EType::Aes256CtsHmacSha1, &password, &salt, 4096) {
                    Ok(hash) => println!("[*]       aes256_cts_hmac_sha1 : {}", hash),
                    Err(e) => eprintln!("[!] AES256 error: {}", e),
                }

                // DES uses password+salt as input
                let des_input = format!("{}{}", password, salt);
                match password_hash(EType::DesCbcMd5, &des_input, &salt, 4096) {
                    Ok(hash) => println!("[*]       des_cbc_md5          : {}", hash),
                    Err(e) => eprintln!("[!] DES error: {}", e),
                }
            } else {
                println!("\n[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!");
            }

            println!();
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
