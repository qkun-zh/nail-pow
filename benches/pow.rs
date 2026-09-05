use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nail_pow::{verify, Challenge};
fn bench_pow(c: &mut Criterion) {
    let mut g = c.benchmark_group("pow");
    for d in [1, 10, 100, 500] {
        let ch = Challenge::generate(d);
        g.bench_function(BenchmarkId::new("prove", d), |b| {
            b.iter(|| black_box(ch.prove().unwrap()))
        });
        let pow = ch.prove().unwrap();
        g.bench_function(BenchmarkId::new("verify", d), |b| {
            b.iter(|| {
                verify(black_box(&pow), d).unwrap();
                black_box(())
            })
        });
    }
    g.finish();
}
criterion_group!(benches, bench_pow);
criterion_main!(benches);
