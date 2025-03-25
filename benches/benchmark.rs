use criterion::{Criterion, black_box, criterion_group, criterion_main};

use sha256::hash; // This code 

// ############# sha2 crate for comparison ###################

use sha2::{Digest, Sha256}; // sha2 crate

pub fn default_hash(msg: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let result = hasher.finalize();

    result.into()
}

// ###########################################################

fn benchmark_hash(c: &mut Criterion) {
    let msg = "Hello, world!";

    c.bench_function("SHA256 - this code", |b| b.iter(|| hash(black_box(msg))));
}

fn benchmark_default(c: &mut Criterion) {
    let msg = "Hello, world!";

    c.bench_function("SHA256 - sha2 crate", |b| {
        b.iter(|| default_hash(black_box(msg)))
    });
}

criterion_group!(benches, benchmark_hash, benchmark_default);
criterion_main!(benches);
