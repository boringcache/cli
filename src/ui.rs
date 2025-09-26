pub fn format_size(bytes: f64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    let mut size = bytes;
    let mut unit = 0usize;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", size as u64, UNITS[unit])
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

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
