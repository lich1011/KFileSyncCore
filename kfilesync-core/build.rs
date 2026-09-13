fn main() {
    #[cfg(feature = "ffi")]
    {
        // Generate the FFI scaffolding from src/kfilestnc_core.udl
        // (UDL approach kept alongside proc-macro exports for compatibility).
        uniffi::generate_scaffolding("src/kfilesync_core.udl").unwrap();
    }
}
