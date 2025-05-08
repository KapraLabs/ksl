use ksl::ksl_bench::run_benchmark;
use ksl::ksl_kapra_shard::{run_shard_benchmark, Transaction};
use ksl::ksl_metrics::BlockResult;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

const PERFORMANCE_THRESHOLD_MS: u64 = 1000; // 1 second threshold
const TPS_THRESHOLD: usize = 10000; // Minimum TPS threshold
const MEMORY_THRESHOLD_MB: usize = 500; // Maximum memory usage in MB

#[tokio::test]
async fn test_shard_benchmark_performance() {
    let shard_id = 1;
    let tx_count = 10000;
    let txs: Vec<Transaction> = (0..tx_count)
        .map(|i| Transaction::mock(i as u64, shard_id))
        .collect();

    let start_time = Instant::now();
    let result = run_shard_benchmark(shard_id, txs).await;
    let duration = start_time.elapsed();

    // Test execution time
    assert!(
        duration.as_millis() < PERFORMANCE_THRESHOLD_MS as u128,
        "Benchmark took too long: {}ms (threshold: {}ms)",
        duration.as_millis(),
        PERFORMANCE_THRESHOLD_MS
    );

    // Test TPS
    let tps = (result.processed_txs as f64 / duration.as_secs_f64()) as usize;
    assert!(
        tps >= TPS_THRESHOLD,
        "TPS too low: {} (threshold: {})",
        tps,
        TPS_THRESHOLD
    );

    // Test success rate
    assert!(
        result.kaprekar_pass_ratio >= 0.95,
        "Kaprekar pass ratio too low: {} (threshold: 0.95)",
        result.kaprekar_pass_ratio
    );
}

#[tokio::test]
async fn test_memory_usage() {
    let shard_id = 1;
    let tx_count = 100000; // Large number of transactions
    let txs: Vec<Transaction> = (0..tx_count)
        .map(|i| Transaction::mock(i as u64, shard_id))
        .collect();

    let start_memory = get_memory_usage();
    let result = run_shard_benchmark(shard_id, txs).await;
    let end_memory = get_memory_usage();
    let memory_used_mb = (end_memory - start_memory) / 1024 / 1024;

    assert!(
        memory_used_mb <= MEMORY_THRESHOLD_MB,
        "Memory usage too high: {}MB (threshold: {}MB)",
        memory_used_mb,
        MEMORY_THRESHOLD_MB
    );
}

#[tokio::test]
async fn test_concurrent_shards() {
    let shard_count = 4;
    let tx_count = 1000;
    let mut handles = vec![];

    for shard_id in 0..shard_count {
        let txs: Vec<Transaction> = (0..tx_count)
            .map(|i| Transaction::mock(i as u64, shard_id))
            .collect();
        
        let handle = tokio::spawn(async move {
            run_shard_benchmark(shard_id, txs).await
        });
        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let mut total_processed = 0;
    let mut total_failed = 0;
    let mut total_gas = 0;

    for result in results {
        let block_result = result.unwrap();
        total_processed += block_result.processed_txs;
        total_failed += block_result.failed_txs;
        total_gas += block_result.gas_used;
    }

    // Verify total throughput
    assert!(total_processed > 0, "No transactions processed");
    assert!(total_failed < total_processed / 10, "Too many failed transactions");
    assert!(total_gas > 0, "No gas used");
}

#[tokio::test]
async fn test_benchmark_regression() {
    let shard_id = 1;
    let tx_count = 1000;
    let iterations = 5;
    let mut durations = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let txs: Vec<Transaction> = (0..tx_count)
            .map(|i| Transaction::mock(i as u64, shard_id))
            .collect();

        let start_time = Instant::now();
        let _result = run_shard_benchmark(shard_id, txs).await;
        let duration = start_time.elapsed();
        durations.push(duration);
    }

    // Calculate average and standard deviation
    let avg_duration: Duration = durations.iter().sum::<Duration>() / iterations as u32;
    let variance: f64 = durations.iter()
        .map(|&d| {
            let diff = d.as_nanos() as f64 - avg_duration.as_nanos() as f64;
            diff * diff
        })
        .sum::<f64>() / iterations as f64;
    let std_dev = variance.sqrt();

    // Check for performance regression
    assert!(
        std_dev < avg_duration.as_nanos() as f64 * 0.1,
        "High performance variance detected: {}ns (avg: {}ns)",
        std_dev,
        avg_duration.as_nanos()
    );
}

#[test]
fn test_full_benchmark_suite() {
    let runtime = Runtime::new().unwrap();
    runtime.block_on(async {
        let start_time = Instant::now();
        run_benchmark().await;
        let duration = start_time.elapsed();

        assert!(
            duration.as_secs() < 300, // 5 minutes threshold
            "Full benchmark suite took too long: {}s",
            duration.as_secs()
        );
    });
}

// Helper function to get current memory usage
fn get_memory_usage() -> usize {
    #[cfg(target_os = "linux")]
    {
        let mut statm = std::fs::read_to_string("/proc/self/statm")
            .expect("Failed to read /proc/self/statm");
        let pages = statm.split_whitespace()
            .nth(1)
            .expect("Failed to parse statm")
            .parse::<usize>()
            .expect("Failed to parse page count");
        pages * 4096 // Page size is 4KB
    }

    #[cfg(not(target_os = "linux"))]
    {
        0 // Return 0 for non-Linux platforms
    }
}

// Helper function to calculate throughput
fn calculate_tps(result: &BlockResult, duration: Duration) -> usize {
    (result.processed_txs as f64 / duration.as_secs_f64()) as usize
}

// Helper function to check performance regression
fn check_performance_regression(current: Duration, baseline: Duration, threshold: f64) -> bool {
    let ratio = current.as_nanos() as f64 / baseline.as_nanos() as f64;
    ratio <= (1.0 + threshold)
}

#[cfg(test)]
mod bench_tests {
    use super::*;

    #[test]
    fn test_performance_helpers() {
        let result = BlockResult {
            processed_txs: 1000,
            failed_txs: 50,
            gas_used: 50000,
            block_time: 100,
            validator_count: 10,
            kaprekar_pass_ratio: 0.95,
        };

        let duration = Duration::from_secs(1);
        let tps = calculate_tps(&result, duration);
        assert_eq!(tps, 1000);

        let baseline = Duration::from_millis(100);
        let current = Duration::from_millis(110);
        assert!(check_performance_regression(current, baseline, 0.2));
    }
} 