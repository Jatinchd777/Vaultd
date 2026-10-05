use std::env;

fn main() {
    println!("Rust: {}", env::var("VAULTD_TEST").unwrap_or_default());
}
