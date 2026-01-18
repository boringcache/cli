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

pub fn workflow_summary(action: &str, completed: usize, total: usize, workspace: &str) {
    blank_line();
    if total == 0 {
        println!("Summary: no entries processed for {}", workspace);
        return;
    }

    if completed == total {
        println!(
            "Summary: {} {} entr{} in '{}'",
            capitalize(action),
            completed,
            if completed == 1 { "y" } else { "ies" },
            workspace
        );
    } else {
        println!(
            "Summary: {} {}/{} entr{} in '{}'",
            capitalize(action),
            completed,
            total,
            if total == 1 { "y" } else { "ies" },
            workspace
        );
    }
}

pub fn restore_summary(tags: &[String], _workspace: &str) {
    blank_line();
    if tags.is_empty() {
        println!("No cache entries restored");
    } else {
        println!("Restored: {}", tags.join(", "));
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capitalize() {
        assert_eq!(capitalize("hello"), "Hello");
        assert_eq!(capitalize("WORLD"), "WORLD");
        assert_eq!(capitalize("rust"), "Rust");
        assert_eq!(capitalize(""), "");
        assert_eq!(capitalize("a"), "A");
    }

    #[test]
    fn test_capitalize_unicode() {
        assert_eq!(capitalize("über"), "Über");
    }
}
