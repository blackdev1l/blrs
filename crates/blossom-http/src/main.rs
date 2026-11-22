#[tokio::main]
async fn main() {
    // Print the human-readable form. Returning the error from main would let
    // Rust format it with `Debug`, which surfaces as `Error: BadSize("4X")`
    // rather than the message the error type actually carries.
    if let Err(err) = blossom_http::run().await {
        eprintln!("blossom: {err}");
        std::process::exit(1);
    }
}
