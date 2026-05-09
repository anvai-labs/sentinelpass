use anyhow::Result;
use rpassword::prompt_password;
use sentinelpass_core::crypto::{analyze_password, generate_password, PasswordGeneratorConfig};
use std::path::PathBuf;

pub fn handle_generate(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
    count: usize,
) -> Result<()> {
    let config = PasswordGeneratorConfig {
        length,
        include_lowercase: lowercase,
        include_uppercase: uppercase,
        include_digits: digits,
        include_symbols: symbols,
        exclude_ambiguous,
    };

    // Validate config
    if let Err(e) = config.validate() {
        anyhow::bail!("Invalid password generator configuration: {}", e);
    }

    println!();
    println!("Generated passwords:");
    println!();

    for i in 0..count {
        let password = generate_password(&config)?;
        println!("  {}: {}", i + 1, password);
    }

    println!();
    Ok(())
}

pub fn handle_check(password: Option<String>) -> Result<()> {
    let password = password
        .map(Ok)
        .unwrap_or_else(|| prompt_password("Enter password to check: "))?;

    let analysis = analyze_password(&password)?;

    println!();
    println!("Password Analysis");
    println!("================");
    println!();

    // Print strength with color
    let color = analysis.strength.color_code();
    let reset = "\x1b[0m";
    println!(
        "Strength:  {}{}{}",
        color,
        analysis.strength.as_str(),
        reset
    );
    println!("Score:     {}/5", analysis.strength.score());
    println!();

    println!("Details:");
    println!("  Length:       {} characters", analysis.length);
    println!("  Entropy:      {:.2} bits", analysis.entropy_bits);
    println!("  Crack time:   {}", analysis.crack_time_human());
    println!();

    println!("Character types:");
    println!(
        "  Lowercase:    {}",
        if analysis.has_lowercase { "✓" } else { "✗" }
    );
    println!(
        "  Uppercase:    {}",
        if analysis.has_uppercase { "✓" } else { "✗" }
    );
    println!(
        "  Digits:       {}",
        if analysis.has_digits { "✓" } else { "✗" }
    );
    println!(
        "  Symbols:      {}",
        if analysis.has_symbols { "✓" } else { "✗" }
    );
    println!();

    if !analysis.warnings.is_empty() {
        println!("Warnings:");
        for warning in &analysis.warnings {
            println!("  ⚠ {}", warning);
        }
        println!();
    }

    if !analysis.suggestions.is_empty() {
        println!("Suggestions:");
        for suggestion in &analysis.suggestions {
            println!("  → {}", suggestion);
        }
        println!();
    }
    Ok(())
}

pub fn handle_health(vault_path: PathBuf, detailed: bool, only_issues: bool) -> Result<()> {
    use sentinelpass_core::crypto::health::HealthScore;

    if !vault_path.exists() {
        anyhow::bail!("No vault found. Use 'sentinelpass init' to create a new vault");
    }

    let master_password = prompt_password("Enter master password: ")?;
    let master_password_bytes = master_password.as_bytes();

    let vault = crate::open_vault_with_password(&vault_path, master_password_bytes)?;

    // Get health summary
    let summary = vault.get_vault_health_summary()?;

    println!();
    println!("Vault Password Health Report");
    println!("===========================");
    println!();

    // Print overall score with color
    let score_color = if summary.overall_score >= 80 {
        "\x1b[32m" // green
    } else if summary.overall_score >= 60 {
        "\x1b[33m" // yellow
    } else if summary.overall_score >= 40 {
        "\x1b[31m" // red
    } else {
        "\x1b[35m" // magenta (critical)
    };
    let reset = "\x1b[0m";
    println!(
        "Overall Health Score: {}{}{}/100",
        score_color, summary.overall_score, reset
    );
    println!();

    println!("Summary:");
    println!("  Total passwords:     {}", summary.total_passwords);
    println!("  Unique passwords:    {}", summary.unique_count);
    println!("  Reused passwords:    {}", summary.reused_count);
    println!("  Weak passwords:      {}", summary.weak_count);
    println!("  Compromised:         {}", summary.compromised_count);
    println!();

    // Print strength distribution
    println!("Strength Distribution:");
    println!("  Excellent:  {}", summary.strength_distribution.excellent);
    println!("  Strong:     {}", summary.strength_distribution.strong);
    println!("  Good:       {}", summary.strength_distribution.good);
    println!("  Fair:       {}", summary.strength_distribution.fair);
    println!("  Weak:       {}", summary.strength_distribution.weak);
    println!("  Critical:   {}", summary.strength_distribution.critical);
    println!();

    // Print weak passwords if any
    if !summary.weak_passwords.is_empty() {
        println!("⚠ Weak Passwords:");
        for weak in &summary.weak_passwords {
            println!("  • {} ({})", weak.title, weak.username);
            println!("    Reason: {}", weak.reason);
        }
        println!();
    }

    // Detailed report if requested
    if detailed {
        let health_report = vault.get_password_health_report()?;
        println!("Detailed Password Report:");
        println!("========================");
        println!();

        for entry in &health_report {
            if only_issues && entry.score >= HealthScore::Good {
                continue;
            }

            let score_color = match entry.score {
                HealthScore::Critical => "\x1b[35m",  // magenta
                HealthScore::Weak => "\x1b[31m",      // red
                HealthScore::Fair => "\x1b[33m",      // yellow
                HealthScore::Good => "\x1b[32m",      // green
                HealthScore::Strong => "\x1b[36m",    // cyan
                HealthScore::Excellent => "\x1b[34m", // blue
            };
            let reset = "\x1b[0m";

            println!("{}{}{}", score_color, entry.score.label(), reset);
            println!("  Title:    {}", entry.title);
            println!("  Username: {}", entry.username);
            println!("  Score:    {}/5", entry.score.score());
            println!("  Strength: {}/5", entry.strength.score);
            println!("  Entropy:  {:.1} bits", entry.strength.entropy_bits);

            if entry.is_compromised {
                println!("  ⚠ COMPROMISED (found in data breaches)");
            }
            if entry.is_reused {
                println!("  ⚠ REUSED across {} sites", entry.reuse_count);
            }
            println!();
        }
    }

    // Print recommendations
    if summary.compromised_count > 0 {
        println!("Recommendations:");
        println!(
            "  • {} compromised password(s) should be changed immediately",
            summary.compromised_count
        );
    }
    if summary.weak_count > 0 {
        println!(
            "  • {} weak password(s) should be strengthened",
            summary.weak_count
        );
    }
    if summary.reused_count > 0 {
        println!(
            "  • {} reused password(s) - use unique passwords for each site",
            summary.reused_count
        );
    }
    if summary.overall_score >= 80 {
        println!("  ✓ Your vault is in good shape!");
    }
    println!();
    Ok(())
}
