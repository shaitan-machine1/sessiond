fn main() {
    if std::env::var_os("CARGO_FEATURE_C_API").is_some() {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libsessiond.so.0");
    }
}
