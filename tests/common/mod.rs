use std::fs;

pub fn load_test_file(file: &str) -> String {
    fs::read_to_string(file).unwrap_or_else(|_| panic!("Failed to read test file: {file}",))
}
