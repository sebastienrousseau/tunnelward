// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Benchmarks of the Tunnelward gateway against NFR-1 to NFR-3, printed
//! as Markdown. Run with `cargo xtask bench` (a release build).
//!
//! ```text
//! tunnelward-bench latency | memory | scaling | all
//! ```

mod latency;
mod memory;
mod scaling;
mod setup;

use setup::Res;

fn latency_report(rows: &[[f64; 6]]) {
    println!("## NFR-1: added latency, 1 KiB MCP call, warm connection\n");
    println!(
        "| Run | Direct p50 | Direct p99 | Gateway p50 | Gateway p99 | Added p50 | Added p99 |"
    );
    println!("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (i, r) in rows.iter().enumerate() {
        println!(
            "| {} | {:.0} µs | {:.0} µs | {:.0} µs | {:.0} µs | {:.0} µs | {:.0} µs |",
            i + 1,
            r[0],
            r[1],
            r[2],
            r[3],
            r[4],
            r[5]
        );
    }
    let spread = |k: usize| {
        let (lo, hi) = rows.iter().fold((f64::MAX, f64::MIN), |(lo, hi), r| {
            (lo.min(r[k]), hi.max(r[k]))
        });
        format!("{lo:.0} to {hi:.0} µs")
    };
    println!(
        "\nAdded p50 over {} runs: {}; added p99: {}.\n",
        rows.len(),
        spread(4),
        spread(5)
    );
}

/// `bytes` in KiB, to a tenth.
fn kib(bytes: u64) -> String {
    let tenths = bytes * 10 / 1024;
    format!("{}.{}", tenths / 10, tenths % 10)
}

async fn run(what: &str) -> Res<()> {
    if matches!(what, "latency" | "all") {
        latency_report(&latency::run().await?);
    }
    if matches!(what, "memory" | "all") {
        let (idle, held) = memory::run().await?;
        println!("## NFR-2: gateway memory\n");
        println!(
            "- Per idle connector connection ({} open): {} KiB",
            memory::IDLE,
            kib(idle)
        );
        println!(
            "- Per request in flight ({} held, each with its HTTP/1.1 client connection): {} KiB\n",
            memory::HELD,
            kib(held)
        );
    }
    if matches!(what, "scaling" | "all") {
        println!("## NFR-3: throughput by gateway worker threads\n");
        println!("| Workers | Calls/s | Against 1 worker | Gateway CPU |");
        println!("| ---: | ---: | ---: | ---: |");
        let one = scaling::measure(1).await?;
        for workers in [1, 2, 4] {
            let (rate, cpu) = if workers == 1 {
                one
            } else {
                scaling::measure(workers).await?
            };
            println!(
                "| {workers} | {rate:.0} | {:.2}x | {cpu:.0}% |",
                rate / one.0
            );
        }
        println!();
    }
    Ok(())
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = || tokio::runtime::Runtime::new();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["peers", connectors, ingress] => runtime()?.block_on(memory::peers(connectors, ingress)),
        ["gateway", workers] => scaling::serve(workers.parse()?),
        [what @ ("latency" | "memory" | "scaling" | "all")] => runtime()?.block_on(run(what)),
        _ => Err("usage: tunnelward-bench latency | memory | scaling | all".into()),
    }
}
