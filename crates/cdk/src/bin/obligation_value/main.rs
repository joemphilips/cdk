//! Private, effect-free maintenance valuation. Input facts are never authority.

#[path = "../../mint/liability_value.rs"]
mod liability_value;
#[path = "../../mint/oracle_evidence.rs"]
mod oracle_evidence;
mod records;
mod requests;

use cdk::Error;

use std::io::{self, Write};

fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("O1_VALUE_REFUSED:arguments");
        std::process::exit(2);
    }
    match records::evaluate(io::stdin().lock()) {
        Ok(result) => match serde_json::to_vec(&result) {
            Ok(mut bytes) if bytes.len() < 65536 => {
                bytes.push(b'\n');
                if io::stdout().lock().write_all(&bytes).is_err() {
                    std::process::exit(2);
                }
            }
            _ => std::process::exit(2),
        },
        Err(error) => {
            // Never print a parser error or input value.
            eprintln!("O1_VALUE_REFUSED:{}", error.token());
            std::process::exit(2);
        }
    }
}
