use sha256::hash;

fn main() {
    let input = "Hello";

    let hash_result = hash(input);

    // Print result

    let hex_string = hash_result
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("");

    println!("Result:\n{}", hex_string);
}
