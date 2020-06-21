/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use p0w::Tree;
use std::env;
use std::time::Instant;

// =========================================== main() =========================================== \\

fn main() {
    let desc = env::var("P0W_DESC").unwrap_or_else(|_| "foobar".into());
    let levels = env::var("P0W_LEVELS")
        .map(|levels| usize::from_str_radix(&levels, 10).unwrap())
        .unwrap_or_else(|_| 24);
    let proofs = env::var("P0W_PROOFS")
        .map(|proofs| usize::from_str_radix(&proofs, 10).unwrap())
        .unwrap_or_else(|_| 8 * levels);

    println!("desc = {}", desc);
    println!("levels = {}", levels);
    println!("proofs = {}", proofs);

    let seq_tree_start = Instant::now();
    let seq_tree = Tree::new(&*desc, levels);
    let seq_tree_time = seq_tree_start.elapsed();

    let par_tree_start = Instant::now();
    let par_tree = Tree::par_new(&*desc, levels);
    let par_tree_time = par_tree_start.elapsed();

    assert!(seq_tree.as_nodes() == par_tree.as_nodes());
    println!("seq tree: {}s", seq_tree_time.as_secs_f64());
    println!("par tree: {}s", par_tree_time.as_secs_f64());

    let nodes = seq_tree.as_nodes().len();
    println!("trees have {} nodes ({} bytes)", nodes, 32 * nodes);

    let proofs_start = Instant::now();
    let proofs = seq_tree.gen_proofs_with(proofs);
    let proofs_time = proofs_start.elapsed();

    println!("proofs: {}s", proofs_time.as_secs_f64());

    let nodes = proofs.as_nodes().len();
    println!("proofs have {} nodes ({} bytes)", nodes, 32 * nodes);

    let verify_start = Instant::now();
    let verify = proofs.verify();
    let verify_time = verify_start.elapsed();

    assert!(verify.is_ok());
    println!("verify: {}s", verify_time.as_secs_f64());
}
