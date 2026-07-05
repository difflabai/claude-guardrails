//! Benchmarks for claude-guardrails
//!
//! Run with: cargo bench

use claude_guardrails::{Config, HookInput, SecurityEngine};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Benchmark creating the security engine
fn bench_engine_creation(c: &mut Criterion) {
    c.bench_function("engine_creation", |b| {
        b.iter(|| {
            let config = Config::default();
            black_box(SecurityEngine::new(config))
        })
    });
}

/// Benchmark parsing JSON input
fn bench_input_parsing(c: &mut Criterion) {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;

    c.bench_function("input_parsing", |b| {
        b.iter(|| black_box(HookInput::from_json(black_box(json)).unwrap()))
    });
}

/// Benchmark a safe command check
fn bench_safe_command(c: &mut Criterion) {
    let config = Config::default();
    let engine = SecurityEngine::new(config);
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;
    let input = HookInput::from_json(json).unwrap();

    c.bench_function("check_safe_command", |b| {
        b.iter(|| black_box(engine.check(black_box(&input))))
    });
}

/// Benchmark a dangerous command check
fn bench_dangerous_command(c: &mut Criterion) {
    let config = Config::default();
    let engine = SecurityEngine::new(config);
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let input = HookInput::from_json(json).unwrap();

    c.bench_function("check_dangerous_command", |b| {
        b.iter(|| black_box(engine.check(black_box(&input))))
    });
}

/// Benchmark a complex command with wrappers
fn bench_wrapped_command(c: &mut Criterion) {
    let config = Config::default();
    let engine = SecurityEngine::new(config);
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"sudo timeout 30 nice -n 10 rm -rf /"}}"#;
    let input = HookInput::from_json(json).unwrap();

    c.bench_function("check_wrapped_command", |b| {
        b.iter(|| black_box(engine.check(black_box(&input))))
    });
}

/// Benchmark file path check
fn bench_file_check(c: &mut Criterion) {
    let config = Config::default();
    let engine = SecurityEngine::new(config);
    let json = r#"{"tool_name":"Read","tool_input":{"file_path":"/path/to/.env"}}"#;
    let input = HookInput::from_json(json).unwrap();

    c.bench_function("check_file_path", |b| {
        b.iter(|| black_box(engine.check(black_box(&input))))
    });
}

/// Benchmark full pipeline (parse + check + output)
fn bench_full_pipeline(c: &mut Criterion) {
    let config = Config::default();
    let engine = SecurityEngine::new(config);
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;

    c.bench_function("full_pipeline", |b| {
        b.iter(|| {
            let input = HookInput::from_json(black_box(json)).unwrap();
            let decision = engine.check(&input);
            let output = claude_guardrails::HookOutput::from_decision(&decision);
            black_box(output.to_json())
        })
    });
}

/// Benchmark compound command check
fn bench_compound_command(c: &mut Criterion) {
    let config = Config::default();
    let engine = SecurityEngine::new(config);
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"npm install && npm run build && npm test"}}"#;
    let input = HookInput::from_json(json).unwrap();

    c.bench_function("check_compound_command", |b| {
        b.iter(|| black_box(engine.check(black_box(&input))))
    });
}

criterion_group!(
    benches,
    bench_engine_creation,
    bench_input_parsing,
    bench_safe_command,
    bench_dangerous_command,
    bench_wrapped_command,
    bench_file_check,
    bench_full_pipeline,
    bench_compound_command,
);

criterion_main!(benches);
