use pulldown_cmark::{html, Options, Parser};
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if (profile == "release" || profile == "dist") && target_env == "msvc" {
        println!("cargo:rustc-link-arg=/DEBUG:NONE");
    }

    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ENV");

    let markdown_input = format!(
        include_str!("./src/proxy/install.md"),
        app_name = env!("CARGO_PKG_NAME")
    );

    let options = Options::empty();
    //options.insert(Options::ENABLE_TABLES);
    let parser = Parser::new_ext(&markdown_input, options);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("install.html");
    fs::write(
        &dest_path,
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
{html_output}
</body>
</html>"#
        ),
    )
    .unwrap();
    println!("cargo:rerun-if-changed=./src/proxy/install.md");
}
