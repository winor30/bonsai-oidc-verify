use oidc::IdentityProvider;
use oidc_verify_methods::{OIDC_VERIFY_ELF, OIDC_VERIFY_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

const TEST_JWT: &str = r#"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjhlNGVhOWY1YjJkODIzNGU3OWYyYzczYTRiMTY4M2E0In0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0OTg3ODE5MjAwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNDk4NzgxOTIwMC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwNzY5MTUwMzUwMDA2MTUwNzE1MTEzMDgyMzY3IiwiYXRfaGFzaCI6IkhLNkVfUDZEaDhZOTNtUk50c0RCMVEiLCJoZCI6ImV4YW1wbGUuY29tIiwiZW1haWwiOiJqc21pdGhAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaWF0IjoxMzUzNjAxMDI2LCJleHAiOjE4NTM2MDQ5MjYsIm5vbmNlIjoiMHhmMzlGZDZlNTFhYWQ4OEY2RjRjZTZhQjg4MjcyNzljZmZGYjkyMjY2In0.C92XFrT8pm_Hg_omZ7l7SqSFMIYTaSk6eSGUPv0trW2I3ucKxXIVlMrFBywXq3-iCMAQ0Bv4W5BkML6okMbgRe7h6HPdoGvMGHjS3_oTxdWQMIWHrdrrMoh_jigenMamEQ_ONOHTiORdY0k5kQ6Z5cUoCV8sVMmhMZB55nS7wse_B7wAmNrAaqXmPkOCkX9qkbwPhPLCWzeRF7PYMHqgM4sHoDOjyEBVKBqbkHJnxVpwzXyMpwqpJvE7VMWU55QGaMqA8rt-KndBfLFTtxkyZn-go1MdvvxdNUAwq9bwNbuOitLaw3gIOTNxHFAF6Era0wQ8Nedz1wDIgjo9ppeDPA"#;

fn main() {
    println!("start oidc_verify");

    let provider = IdentityProvider::Test;
    let (receipt, claims_data) = oidc_verify_jwt(TEST_JWT, provider);

    println!("claims_data: {:?}", claims_data);

    // Verify receipt, panic if it's wrong
    receipt.verify(OIDC_VERIFY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct image ID?",
    );
    print!("Verified receipt!\n");
}

fn oidc_verify_jwt(jwt: &str, provider: IdentityProvider) -> (Receipt, Vec<u8>) {
    println!(
        "oidc_verify_jwt start jwt: {:?} provider: {:?}",
        jwt, provider
    );
    let env = ExecutorEnv::builder()
        .write(&provider)
        .unwrap()
        .write(&jwt)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();
    println!("create prover");

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(env, OIDC_VERIFY_ELF).unwrap();
    println!("receipt: {:?}", receipt);

    let claims_data: Vec<u8> = receipt.journal.decode().expect(
        "Journal output should deserialize into the same types (& order) that it was written",
    );
    println!("claims_data: {:?}", claims_data);

    (receipt, claims_data)
}
