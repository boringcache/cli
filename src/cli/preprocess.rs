fn long_option_requires_value(command: &str, option: &str) -> bool {
    match command {
        "save" => matches!(option, "--exclude" | "--recipient"),
        "restore" => matches!(option, "--identity"),
        "run" | "exec" => matches!(
            option,
            "--exclude"
                | "--recipient"
                | "--identity"
                | "--proxy"
                | "--metadata-hint"
                | "--host"
                | "--endpoint-host"
                | "--port"
        ),
        "ls" => matches!(option, "--limit" | "--page"),
        "serve" | "docker-registry" | "cache-registry" => {
            matches!(option, "--host" | "--port" | "--metadata-hint")
        }
        _ => false,
    }
}

fn short_option_requires_value(command: &str, option: &str) -> bool {
    match command {
        "run" | "exec" => option == "-p" || (option.starts_with("-p") && option.len() > 2),
        "serve" | "docker-registry" | "cache-registry" => {
            option == "-p" || (option.starts_with("-p") && option.len() > 2)
        }
        _ => false,
    }
}

fn positional_args_with_indices<'a>(
    command: &str,
    args_after_command: &'a [String],
) -> Vec<(usize, &'a String)> {
    let mut positional = Vec::new();
    let mut skip_next = false;
    let mut positional_mode = false;

    for (index, arg) in args_after_command.iter().enumerate() {
        if positional_mode {
            positional.push((index, arg));
            continue;
        }

        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "--" {
            positional_mode = true;
            continue;
        }

        if arg.starts_with("--") {
            let option_name = arg.split('=').next().unwrap_or(arg.as_str());
            if !arg.contains('=') && long_option_requires_value(command, option_name) {
                skip_next = true;
            }
            continue;
        }

        if arg.starts_with('-') && arg != "-" {
            if short_option_requires_value(command, arg) && arg.len() == 2 {
                skip_next = true;
            }
            continue;
        }

        positional.push((index, arg));
    }

    positional
}

pub fn prepare_args(mut args: Vec<String>) -> Vec<String> {
    if args.len() < 2 {
        return args;
    }

    let command = &args[1];
    if !matches!(
        command.as_str(),
        "save"
            | "restore"
            | "delete"
            | "check"
            | "ls"
            | "serve"
            | "docker-registry"
            | "cache-registry"
    ) {
        return args;
    }

    let positional_args = positional_args_with_indices(command, &args[2..]);
    let needs_workspace_injection = match command.as_str() {
        "ls" => positional_args.is_empty(),
        "save" | "restore" => positional_args.len() == 1 && positional_args[0].1.contains(':'),
        "delete" | "check" => positional_args.len() == 1 && !positional_args[0].1.contains('/'),
        "serve" | "docker-registry" | "cache-registry" => positional_args
            .first()
            .map(|(_, arg)| !arg.contains('/'))
            .unwrap_or(false),
        _ => false,
    };

    if needs_workspace_injection
        && let Some(default_workspace) = crate::command_support::configured_workspace()
    {
        if command == "ls" || positional_args.is_empty() {
            args.push(default_workspace);
        } else {
            let first_pos_idx = positional_args[0].0 + 2;
            args.insert(first_pos_idx, default_workspace);
        }
    }

    args
}
