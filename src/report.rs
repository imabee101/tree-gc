use crate::exec::{JEntry, Outcome};
use crate::model::{Item, Kind, Plan, Verdict};
use crate::util::*;
use std::collections::BTreeMap;

fn what(it: &Item) -> String {
    let mut s = display_path(&it.path);
    if let Some(b) = &it.branch {
        if it.kind == Kind::Branch {
            s = format!("{s} [{b}]");
        }
    }
    if let Some(r) = &it.rule {
        s = format!("{s}  ({r})");
    }
    s
}

fn row(now: i64, it: &Item) -> String {
    format!(
        "  {:<10} {:<9} {:>6} {:>8}  {}  {}\n{:>40}{}",
        it.id,
        it.kind.label(),
        fmt_age(now, it.last_activity),
        fmt_bytes(it.bytes),
        it.action.map(|a| a.label()).unwrap_or(""),
        what(it),
        "",
        it.reasons.join("; ")
    )
}

pub fn header(plan: &Plan) -> String {
    let mode = if plan.enforce { "ENFORCE" } else { "SHADOW (enforce=false: nothing will be changed)" };
    let sim = if plan.simulated {
        format!("  SIMULATED clock: {} ({:+}d)", fmt_ts(plan.now), (plan.now - plan.generated_at) / DAY)
    } else {
        String::new()
    };
    format!("tree-gc  {}  mode: {mode}{sim}", fmt_ts(plan.generated_at))
}

pub fn print_plan(plan: &Plan, all: bool) {
    println!("{}\n", header(plan));
    let groups = [
        (Verdict::Eligible, "WOULD ACT"),
        (Verdict::Active, "KEPT: recently active"),
        (Verdict::Protected, "PROTECTED: holds irreplaceable or in-use state"),
    ];
    for (v, title) in groups {
        let items: Vec<&Item> = plan.items.iter().filter(|i| i.verdict == v).collect();
        let bytes: u64 = items.iter().filter_map(|i| i.bytes).sum();
        println!("{title} ({} items{})", items.len(), if bytes > 0 { format!(", {}", fmt_bytes(Some(bytes))) } else { String::new() });
        if v == Verdict::Eligible || all {
            println!("  {:<10} {:<9} {:>6} {:>8}  ACTION  PATH / WHY", "ID", "KIND", "IDLE", "SIZE");
            for it in &items {
                println!("{}", row(plan.now, it));
            }
        } else {
            print_reason_summary(&items, 8);
        }
        println!();
    }
    for n in &plan.notes {
        println!("note: {n}");
    }
}

/// Group reasons by their "shape" (text before ':' and digits stripped).
fn print_reason_summary(items: &[&Item], top: usize) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for it in items {
        if let Some(r) = it.reasons.first() {
            let key: String = r.split(':').next().unwrap_or(r).chars().filter(|c| !c.is_ascii_digit()).collect();
            *counts.entry(format!("{:<9} {}", it.kind.label(), key.trim())).or_default() += 1;
        }
    }
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    for (k, n) in v.iter().take(top) {
        println!("  {n:>5}  {k}");
    }
    if v.len() > top {
        println!("  ... ({} more groups; use --all)", v.len() - top);
    }
}

pub fn print_survey(plan: &Plan) {
    println!("{}\n", header(plan));
    println!("{:<10} {:>9} {:>9} {:>9}   {:>10} {:>10}", "KIND", "ELIGIBLE", "ACTIVE", "PROTECTED", "RECLAIM", "TOTAL SEEN");
    for k in Kind::ALL {
        let of: Vec<&Item> = plan.items.iter().filter(|i| i.kind == k).collect();
        let c = |v: Verdict| of.iter().filter(|i| i.verdict == v).count();
        let rec: u64 = of.iter().filter(|i| i.verdict == Verdict::Eligible).filter_map(|i| i.bytes).sum();
        let tot: u64 = of.iter().filter_map(|i| i.bytes).sum();
        println!(
            "{:<10} {:>9} {:>9} {:>9}   {:>10} {:>10}",
            k.label(),
            c(Verdict::Eligible),
            c(Verdict::Active),
            c(Verdict::Protected),
            fmt_bytes(Some(rec)),
            fmt_bytes(Some(tot))
        );
    }
    println!("\n(RECLAIM counts quarantined items too; their space returns only when purged.)");
    println!("\nWhy things are protected:");
    let prot: Vec<&Item> = plan.items.iter().filter(|i| i.verdict == Verdict::Protected).collect();
    print_reason_summary(&prot, 15);

    let mut repos: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for it in plan.items.iter().filter(|i| matches!(i.kind, Kind::Branch | Kind::Worktree | Kind::StaleWorktreeMeta)) {
        let r = it.repo.as_deref().map(display_path).unwrap_or_default();
        let e = repos.entry(r).or_default();
        match it.verdict {
            Verdict::Eligible => e.0 += 1,
            Verdict::Active => e.1 += 1,
            Verdict::Protected => e.2 += 1,
        }
    }
    println!("\nPer repository (branches + worktrees)  eligible/active/protected:");
    for (r, (a, b, c)) in repos {
        println!("  {a:>4} {b:>4} {c:>4}  {r}");
    }
    for n in &plan.notes {
        println!("note: {n}");
    }
}

pub fn print_outcome(o: &Outcome) {
    for e in &o.done {
        println!("done  {:<40} {:?} {:?} {}", e.jid, e.action, e.status, display_path(&e.path));
    }
    for (i, why) in &o.skipped {
        println!("skip  {} {}: {why}", i.kind.label(), display_path(&i.path));
    }
    for (i, why) in &o.failed {
        println!("FAIL  {} {}: {why}", i.kind.label(), display_path(&i.path));
    }
    if let Some(s) = &o.stopped_early {
        println!("stopped early: {s}");
    }
    let bytes: u64 = o.done.iter().filter_map(|e| e.bytes).sum();
    println!(
        "summary: {} done ({}), {} skipped (changed since plan), {} failed",
        o.done.len(),
        fmt_bytes(Some(bytes)),
        o.skipped.len(),
        o.failed.len()
    );
}

pub fn print_journal(entries: &[JEntry], all: bool) {
    for e in entries {
        if !all && !matches!(e.status, crate::exec::JStatus::Quarantined | crate::exec::JStatus::Archived | crate::exec::JStatus::Pending) {
            continue;
        }
        println!(
            "{:<36} {:<16} {:<12} {:>8}  {}{}",
            e.jid,
            fmt_ts(e.ts),
            format!("{:?}", e.status),
            fmt_bytes(e.bytes),
            display_path(&e.path),
            e.branch.as_ref().map(|b| format!(" [{b}]")).unwrap_or_default()
        );
    }
}
