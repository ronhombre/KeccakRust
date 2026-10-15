use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use criterion::criterion_group;
use criterion::criterion_main;
use keccakrust::*;
use std::hint::black_box;

fn sha3_224(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA3-224");

    // Test different input sizes to see how performance scales
    for size in [0, 64, 1024, 16 * 1024, 64 * 1024].iter() {
        let input = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("hash", *size as u32), &input, |b, data| {
            b.iter(|| {
                let mut sha3_224 = SHA3_224::new_input_stream();
                sha3_224.write_bytes(data);
                let mut sha3_224_output = sha3_224.close();
                let mut hash_224 = [0u8; 28];
                sha3_224_output.next_bytes(&mut hash_224);
                black_box(hash_224);
            });
        });
    }

    group.finish();
}

fn shake128_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHAKE");
    let output_size = 16;
    group.throughput(Throughput::Bytes(output_size as u64));

    group.bench_function("128_output", |b| {
        let mut shake128 = SHAKE_128::new_input_stream();
        shake128.write_bytes(&[0u8; 0]);
        let mut shake128_output = shake128.close();
        b.iter(|| {
            let mut hash_shake128 = [0u8; 16];
            shake128_output.next_bytes(&mut hash_shake128);
            black_box(hash_shake128);
        });
    });

    group.finish();
}

fn shake256_output(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHAKE");
    let output_size = 32;
    group.throughput(Throughput::Bytes(output_size as u64));

    group.bench_function("256_output", |b| {
        let mut shake256 = SHAKE_256::new_input_stream();
        shake256.write_bytes(&[0u8; 0]);
        let mut shake256_output = shake256.close();
        b.iter(|| {
            let mut hash_shake256 = [0u8; 32];
            shake256_output.next_bytes(&mut hash_shake256);
            black_box(hash_shake256);
        });
    });

    group.finish();
}
criterion_group!(benches, shake128_output, shake256_output);
criterion_main!(benches);
