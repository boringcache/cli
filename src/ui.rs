mod summary;

pub use summary::{restore_summary, workflow_summary};

pub fn info(message: &str) {
    println!("{message}");
}

pub fn warn(message: &str) {
    eprintln!("warning: {message}");
}

pub fn error(message: &str) {
    eprintln!("error: {message}");
}

pub fn blank_line() {
    println!();
}
