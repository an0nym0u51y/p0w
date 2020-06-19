/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// ======================================== Documentation ======================================= \\

//! # Merkle tree Proof-of-Work (PoW)
//!
//! This crate provides an implementation of the
//! [following paper](https://hal-mines-paristech.archives-ouvertes.fr/hal-00752925/):
//! > Fabien Coelho. An (Almost) Constant-E ort Solution-Veri cation Proof-of-Work Protocol based
//! > on Merkle Trees. 1st international conference on Progress in cryptology, Jun 2008, Casablanca,
//! > Morocco. pp.Pages 80-93. ⟨hal-00752925⟩
//!
//! ## How does it work?
//!
//! [`Tree::new()`] creates a new Merkle tree with a specified service description and number of
//! levels, in which leaves are equal to `hmac(h(desc), leaf)` (with `desc` the service description,
//! and `leaf` the zero-based index of the leaf).
//!
//! [`Tree::proofs()`] then creates a [`Proofs`] for the tree with a specified number of
//! evenly-distributed, randomly selected leaves, their sibling and the internal nodes required to
//! prove the validity of the tree up to its root node.
//!
//! ## Example
//!
//! ```rust
//! use p0w::Tree;
//!
//! let tree = Tree::new("foobar", 16);
//! let proofs = tree.proofs(4);
//!
//! assert!(proofs.verify().is_ok());
//! ```

// =========================================== Imports ========================================== \\

use blake3::{Hash, Hasher};
use rand::distributions::uniform::Uniform;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ============================================ Types =========================================== \\

#[derive(Debug)]
/// A Merkle tree used to generate a [`Proofs`]
pub struct Tree {
    desc: String,
    levels: usize,
    nodes: Vec<Hash>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The actual Proof-of-work
pub struct Proofs {
    desc: String,
    levels: usize,
    proofs: usize,
    nodes: BTreeMap<usize, [u8; 32]>,
}

#[derive(Error, Debug)]
/// The error type returned by [`Proofs::verify()`]
pub enum Error {
    #[error("missing leaf {0} in proof")]
    MissingLeaf(usize),
    #[error("too many nodes in proof (expected {expected} nodes; contains {nodes} nodes)")]
    TooManyNodes { expected: usize, nodes: usize },
    #[error("wrong hash for leaf {0}")]
    WrongLeafHash(usize),
}

// ========================================== leaves() ========================================== \\

#[inline]
fn nodes(levels: usize) -> usize {
    (1 << levels) - 1
}

#[inline]
fn leaves(levels: usize) -> usize {
    1 << (levels - 1)
}

// ========================================== impl Tree ========================================= \\

impl Tree {
    // ==================================== Constructors ==================================== \\

    /// Creates a new merkle tree with the specified service description and number of levels
    /// (including the root).
    ///
    /// Increasing the number of levels will also increase the time spent computing the tree (ie.
    /// this is the way to increase the 'difficulty').
    ///
    /// ## Panics
    ///
    /// This function will panic if `levels` is less than `2`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.proofs(2);
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn new<Desc: ToString>(desc: Desc, levels: usize) -> Self {
        assert!(levels > 1);

        let desc = desc.to_string();
        let service = blake3::hash(desc.as_bytes());

        let mut nodes = vec![Hash::from([0; 32]); nodes(levels)];
        let offset = leaves(levels) - 1;
        let leaves = nodes.get_mut(offset..).unwrap();

        for (leaf, node) in leaves.iter_mut().enumerate() {
            *node = blake3::keyed_hash(service.as_bytes(), &leaf.to_le_bytes()[..]);
        }

        for node in (0..offset).rev() {
            nodes[node] = Hasher::new()
                .update(&nodes[2 * node + 1].as_bytes()[..])
                .update(&nodes[2 * node + 2].as_bytes()[..])
                .finalize();
        }

        Tree {
            desc,
            levels,
            nodes,
        }
    }

    // ======================================== Read ======================================== \\

    /// Returns the tree's service description (as passed to [`Tree::new()`]).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 4);
    /// assert_eq!(tree.description(), "foobar");
    /// ```
    pub fn description(&self) -> &str {
        &self.desc
    }

    /// Returns the number of levels (including the root) this tree contains (as passed to
    /// [`Tree::new()`]).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 4);
    /// assert_eq!(tree.levels(), 4);
    /// ```
    pub fn levels(&self) -> usize {
        self.levels
    }

    /// Generates a new [`Proofs`] containing the hashes of `2 * proofs` leaves (because the sibling
    /// of each leaf is required) and all internal nodes required to prove the validity of the tree
    /// up to its root node.
    ///
    /// This method selects the leaves in a random but evenly-distributed manner using a
    /// [`ChaCha20Rng`] instance seeded with the tree's root node.
    ///
    /// ## Panics
    ///
    /// This function will panic if `proofs` is `0` or *greater than* the number of leaves the tree
    /// contains (`leaves = 2 ^ (levels - 1)`).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.proofs(2);
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn proofs(&self, proofs: usize) -> Proofs {
        assert!(proofs > 0);
        assert!(proofs <= leaves(self.levels));

        let mut nodes = BTreeMap::new();
        let mut visited = BTreeSet::new();

        // seed the rng with the root node
        let mut rng = ChaCha20Rng::from_seed(self.nodes[0].into());
        let chunks = leaves(self.levels) as f64 / proofs as f64;
        let offset = leaves(self.levels) - 1;

        // randomly select the leaves in an evenly-distributed manner
        for proof in 0..proofs {
            let distribution = Uniform::new(
                chunks * proof as f64,
                chunks * (proof + 1) as f64,
            );

            let leaf = distribution.sample(&mut rng).ceil() as usize;
            let node = offset + leaf;
            nodes.insert(node, self.nodes[node].into());
            visited.insert(node);
        }

        // include the nodes required to prove the validity of the tree
        for right in (1..self.nodes.len()).rev().step_by(2) {
            let left = right - 1;

            match (
                (visited.contains(&left) || visited.contains(&(2 * left + 1))),
                (visited.contains(&right) || visited.contains(&(2 * right + 1))),
            ) {
                (true, true) => (),
                (true, false) => {
                    nodes.insert(right, self.nodes[right].into());
                }
                (false, true) => {
                    nodes.insert(left, self.nodes[left].into());
                }
                (false, false) => continue,
            }

            visited.insert(left);
            visited.insert(right);
        }

        Proofs {
            desc: self.desc.clone(),
            levels: self.levels,
            proofs,
            nodes,
        }
    }
}

// ========================================= impl Proof ========================================= \\

impl Proofs {
    // ======================================== Read ======================================== \\

    /// Returns the tree's service description (as passed to [`Tree::new()`]).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 4);
    /// let proofs = tree.proofs(1);
    ///
    /// assert_eq!(proofs.description(), "foobar");
    /// ```
    pub fn description(&self) -> &str {
        &self.desc
    }

    /// Returns the number of levels (including the root) this tree contains (as passed to
    /// [`Tree::new()`]).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 4);
    /// let proofs = tree.proofs(1);
    ///
    /// assert_eq!(proofs.levels(), 4);
    /// ```
    pub fn levels(&self) -> usize {
        self.levels
    }

    /// Returns the number of minimum number of leaves included in the proofs (as passed to
    /// [`Tree::proofs()`]).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.proofs(2);
    ///
    /// assert_eq!(proofs.proofs(), 2);
    /// ```
    pub fn proofs(&self) -> usize {
        self.proofs
    }

    /// Verifies that the proofs are valid, returning an [`Error`] otherwise.
    ///
    /// This function does the following verification (in order):
    /// - the nodes that are included in the proofs allow to verify the tree up to its root
    /// - there are no unnecessary nodes included in the proofs
    /// - the included leaves have the right hashes
    /// - the right leaves were included
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.proofs(2);
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn verify(&self) -> Result<(), Error> {
        let offset = leaves(self.levels) - 1;
        let mut expected = 0;
        let mut nodes = BTreeSet::new();
        let mut queue = VecDeque::with_capacity(self.nodes.len());
        queue.push_back(0);

        // verify that the included nodes allow for the verification of the proof
        while let Some(node) = queue.pop_front() {
            if self.nodes.contains_key(&node) {
                expected += 1;

                continue;
            }

            if node >= offset {
                return Err(Error::MissingLeaf(node - offset));
            }

            nodes.insert(node);
            queue.push_back(2 * node + 1);
            queue.push_back(2 * node + 2);
        }

        // return an error if unnecessary nodes are included in the proofs
        if expected != self.nodes.len() {
            return Err(Error::TooManyNodes {
                expected,
                nodes: self.nodes.len(),
            });
        }

        // re-compute the included leaves' hashes and compare them against the ones in the proofs
        let service = blake3::hash(self.desc.as_bytes());
        for (leaf, hash) in self
            .nodes
            .range(offset..)
            .map(|(node, hash)| ((node - offset), hash))
        {
            if Hash::from(*hash) != blake3::keyed_hash(service.as_bytes(), &leaf.to_le_bytes()[..]) {
                return Err(Error::WrongLeafHash(leaf));
            }
        }

        // re-compute the internal nodes up to the root node
        let mut hashes = self.nodes.clone();
        for node in nodes.iter().rev() {
            hashes.insert(
                *node,
                Hasher::new()
                    .update(&hashes[&(2 * node + 1)])
                    .update(&hashes[&(2 * node + 2)])
                    .finalize()
                    .into(),
            );
        }

        let mut rng = ChaCha20Rng::from_seed(hashes[&0]);
        let chunks = leaves(self.levels) as f64 / self.proofs as f64;

        // verify that the right leaves were included
        for proof in 0..self.proofs {
            let distribution = Uniform::new(
                chunks * proof as f64,
                chunks * (proof + 1) as f64,
            );

            let leaf = distribution.sample(&mut rng).ceil() as usize;
            if !self.nodes.contains_key(&(leaf + offset)) {
                return Err(Error::MissingLeaf(leaf));
            }
        }

        Ok(())
    }
}
