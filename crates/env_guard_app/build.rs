fn main() {
    slint_build::compile("ui/app.slint").unwrap();
    println!("cargo:rerun-if-env-changed=SQLCIPHER_LIB_DIR");
    println!("cargo:rerun-if-env-changed=OPENSSL_DIR");
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=bcrypt");
    }
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
    let timestamp = std::env::var("SOURCE_DATE_EPOCH")
        .map(|s| s.parse::<i64>().unwrap_or(0))
        .unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        });
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);
    println!("cargo:rustc-env=BUILD_TARGET={}", std::env::var("TARGET").unwrap_or_default());
}
