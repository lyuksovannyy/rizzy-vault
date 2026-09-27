//! Explorer CLI. `cargo run --release -- <family|flavour|all|exhaustive|random-all|list> [options]`;
//! see README.md.
#![forbid(unsafe_code)]

use merge_model::config::{Config, PRESETS};
use merge_model::explore::{
    default_threads, print_report, run_exhaustive_par, run_random_par, seed_events, show_order,
};
use merge_model::random::{FLAVORS, Flavor};
use merge_model::scenarios::{FAMILIES, family};

fn usage() -> ! {
    let fams: Vec<&str> = FAMILIES.iter().map(|(n, _)| *n).collect();
    let flavs: Vec<&str> = FLAVORS.iter().map(|f| f.family()).collect();
    eprintln!(
        "usage: merge-model <family|flavour|all|exhaustive|random-all|list> [--config {}|all] [--set key=value,...] [--hist N] [--seeds N] [--seed-start N] [--quick] [--threads N] [--no-traces] [--max-traces N] [--only TEXT] [--scenario TEXT] [--order a,b,...] [--events] [--seed-list]\n\
         families: {}\n\
         random flavours: {}",
        PRESETS.join("|"),
        fams.join(", "),
        flavs.join(", ")
    );
    std::process::exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut target: Option<String> = None;
    let mut configs: Vec<String> = vec!["literal".to_string()];
    let mut sets: Vec<(String, String)> = Vec::new();
    let mut hist = 2usize;
    let mut seeds = 500u64;
    let mut seed_start = 1u64;
    let mut quick = false;
    let mut traces = true;
    let mut max_traces = 12usize;
    let mut only: Option<String> = None;
    let mut scen_filter: Option<String> = None;
    let mut threads = default_threads();
    let mut order: Option<Vec<usize>> = None;
    let mut events = false;
    let mut seed_list = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let mut val = || {
            i += 1;
            args.get(i).cloned().unwrap_or_else(|| usage())
        };
        match a {
            "--config" => {
                let v = val();
                configs = if v == "all" {
                    PRESETS.iter().map(|s| s.to_string()).collect()
                } else {
                    v.split(',').map(|s| s.to_string()).collect()
                };
            }
            "--set" => {
                for kv in val().split(',') {
                    let (k, v) = kv.split_once('=').unwrap_or_else(|| usage());
                    sets.push((k.to_string(), v.to_string()));
                }
            }
            "--hist" => hist = val().parse().unwrap_or_else(|_| usage()),
            "--seeds" => seeds = val().parse().unwrap_or_else(|_| usage()),
            "--seed-start" => seed_start = val().parse().unwrap_or_else(|_| usage()),
            "--max-traces" => max_traces = val().parse().unwrap_or_else(|_| usage()),
            "--threads" => threads = val().parse().unwrap_or_else(|_| usage()),
            "--only" => only = Some(val()),
            "--scenario" => scen_filter = Some(val()),
            "--order" => {
                order = Some(
                    val()
                        .split(',')
                        .map(|x| x.parse().unwrap_or_else(|_| usage()))
                        .collect(),
                )
            }
            "--quick" => quick = true,
            "--no-traces" => traces = false,
            "--events" => events = true,
            "--seed-list" => seed_list = true,
            "-h" | "--help" => usage(),
            other if !other.starts_with("--") && target.is_none() => {
                target = Some(other.to_string())
            }
            _ => usage(),
        }
        i += 1;
    }
    let target = target.unwrap_or_else(|| usage());
    if target == "list" {
        for (n, f) in FAMILIES {
            println!("{n}: {} scenarios", f(false).len());
        }
        for f in FLAVORS {
            println!("{}: seeded random scenarios", f.family());
        }
        return;
    }
    let mut names: Vec<String> = Vec::new();
    if target == "all" || target == "exhaustive" {
        names.extend(FAMILIES.iter().map(|(n, _)| n.to_string()));
    }
    // `random` is the merge-only flavour; `random-all` runs every flavour.
    if target == "all" || target == "random-all" {
        names.extend(FLAVORS.iter().map(|f| f.family().to_string()));
    }
    if names.is_empty() {
        names.push(target);
    }
    for name in &names {
        for c in &configs {
            let mut cfg = Config::preset(c, hist).unwrap_or_else(|| usage());
            for (k, v) in &sets {
                if !cfg.set(k, v) {
                    eprintln!("unknown --set {k}={v}");
                    usage();
                }
            }
            if let Some(flavor) = Flavor::by_name(name) {
                if events {
                    for sd in seed_start..seed_start + seeds {
                        println!("{}", seed_events(flavor, sd, &cfg));
                    }
                    continue;
                }
                let report = run_random_par(flavor, seed_start..seed_start + seeds, &cfg, threads);
                println!(
                    "{}",
                    print_report(
                        &report,
                        &cfg,
                        traces,
                        max_traces,
                        only.as_deref(),
                        seed_list
                    )
                );
                continue;
            }
            let f = family(name).unwrap_or_else(|| usage());
            let mut scns = f(quick);
            if let Some(sf) = &scen_filter {
                scns.retain(|s| s.name.contains(sf.as_str()));
            }
            if let Some(o) = &order {
                if let Some(scn) = scns.first() {
                    println!("{}", show_order(scn, &cfg, o));
                }
                continue;
            }
            let report = run_exhaustive_par(name, scns, &cfg, threads);
            println!(
                "{}",
                print_report(
                    &report,
                    &cfg,
                    traces,
                    max_traces,
                    only.as_deref(),
                    seed_list
                )
            );
        }
    }
}
