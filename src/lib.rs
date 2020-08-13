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
//! [`Tree::gen_proofs(_with)?()`] then creates a [`Proofs`] for the tree with an eventually
//! specified number of evenly-distributed, randomly selected leaves, their sibling and the internal
//! nodes required to prove the validity of the tree.
//!
//! ## Example
//!
//! ```rust
//! use p0w::Tree;
//!
//! let tree = Tree::new("foobar", 16);
//! let proofs = tree.gen_proofs();
//!
//! assert!(proofs.verify().is_ok());
//! ```
//!
//! [`Tree::gen_proofs(_with)?()`]: `Tree::gen_proofs()`

// =========================================== Imports ========================================== \\

use blake3::{Hash, Hasher};
use rand::distributions::uniform::Uniform;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// ============================================ Types =========================================== \\

#[derive(Debug)]
/// A Merkle tree used to generate a [`Proofs`]
pub struct Tree {
    desc: Vec<u8>,
    levels: usize,
    nodes: Vec<Hash>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
/// The actual Proof-of-work
pub struct Proofs {
    desc: Vec<u8>,
    levels: usize,
    proofs: usize,
    nodes: BTreeMap<usize, [u8; 32]>,
}

#[derive(Debug)]
#[cfg_attr(feature = "thiserror", derive(Error))]
/// The error type returned by [`Proofs::verify()`]
pub enum Error {
    #[cfg_attr(feature = "thiserror", error("missing leaf {0} in proof"))]
    MissingLeaf(usize),
    #[cfg_attr(
        feature = "thiserror",
        error("too many nodes in proof (expected {expected} nodes; contains {nodes} nodes)")
    )]
    TooManyNodes { expected: usize, nodes: usize },
    #[cfg_attr(feature = "thiserror", error("wrong hash for leaf {0}"))]
    WrongLeafHash(usize),
}

// ========================================== impl Tree ========================================= \\

impl Tree {
    // ==================================== Constructors ==================================== \\

    /// Creates a new Merkle tree with the specified service description and number of levels
    /// (including the root).
    ///
    /// Increasing the number of levels will also increase the time spent computing the tree (ie.
    /// this is the way to increase the 'difficulty').
    ///
    /// ## Panics
    ///
    /// This function will panic if `levels` is *less than* `2`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs();
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn new<Desc: Into<Vec<u8>>>(desc: Desc, levels: usize) -> Self {
        assert!(levels > 1);

        let desc = desc.into();
        let service = blake3::hash(&desc);

        let mut nodes = vec![Hash::from([0; 32]); Self::tree_nodes(levels)];
        let leaves = nodes.get_mut(Self::offset(levels - 1)..).unwrap();

        for (leaf, node) in leaves.iter_mut().enumerate() {
            *node = blake3::keyed_hash(service.as_bytes(), &leaf.to_le_bytes()[..]);
        }

        for node in (0..Self::offset(levels - 1)).rev() {
            let base = node << 1;
            nodes[node] = Hasher::new()
                .update(&nodes[base + 1].as_bytes()[..])
                .update(&nodes[base + 2].as_bytes()[..])
                .finalize();
        }

        Tree {
            desc,
            levels,
            nodes,
        }
    }

    #[cfg(feature = "parallel")]
    #[cfg_attr(docsrs, doc(cfg(feature = "parallel")))]
    /// Creates a new Merkle tree with the specified service description and number of levels
    /// (including the root) using [`rayon`] to parallelize the hash operations.
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
    /// let tree = Tree::par_new("foobar", 8);
    /// let proofs = tree.gen_proofs();
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn par_new<Desc: Into<Vec<u8>>>(desc: Desc, levels: usize) -> Self {
        assert!(levels > 1);

        let desc = desc.into();
        let service = blake3::hash(&desc);

        let mut nodes = vec![Hash::from([0; 32]); Self::tree_nodes(levels)];

        nodes[Self::offset(levels - 1)..]
            .par_iter_mut()
            .enumerate()
            .for_each(|(leaf, node)| {
                *node = blake3::keyed_hash(service.as_bytes(), &leaf.to_le_bytes()[..]);
            });

        for level in (0..(levels - 1)).rev() {
            let (cur, prev) = nodes[Self::offset(level)..Self::offset(level + 2)]
                .split_at_mut(Self::nodes(level));

            prev.par_chunks(2).zip(cur).for_each(|(prev, node)| {
                *node = Hasher::new()
                    .update(&prev[0].as_bytes()[..])
                    .update(&prev[1].as_bytes()[..])
                    .finalize();
            });
        }

        Tree {
            desc,
            levels,
            nodes,
        }
    }

    // ======================================= Helpers ====================================== \\

    #[inline]
    fn tree_nodes(levels: usize) -> usize {
        (1 << levels) - 1
    }

    #[inline]
    fn leaves(levels: usize) -> usize {
        1 << (levels - 1)
    }

    #[inline]
    fn nodes(level: usize) -> usize {
        1 << level
    }

    #[inline]
    fn offset(level: usize) -> usize {
        Self::nodes(level) - 1
    }

    // ======================================== Read ======================================== \\

    /// Returns the tree's service description (as passed to [`Tree::new()`]).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// assert_eq!(tree.description(), b"foobar");
    /// ```
    pub fn description(&self) -> &[u8] {
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
    /// let tree = Tree::new("foobar", 8);
    /// assert_eq!(tree.levels(), 8);
    /// ```
    pub fn levels(&self) -> usize {
        self.levels
    }

    /// Returns the tree's nodes in order (level by level).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    ///
    /// let nodes = tree.as_nodes();
    /// assert_eq!(nodes.len(), 255);
    /// ```
    pub fn as_nodes(&self) -> &[Hash] {
        &self.nodes
    }

    /// Generates a new [`Proofs`] containing `16 * levels` (as passed to [`Tree::new()`])
    /// evenly-distributed, randomly selected leaves along with all internal nodes required to prove
    /// the validity of the tree.
    ///
    /// This method selects the leaves in a random but evenly-distributed manner by seeding a
    /// [`ChaCha20Rng`] instance with the tree's root node, and generating `8 * levels` numbers in
    /// the range `0..(leaves / 8)`.
    ///
    /// This method is equivalent to calling [`Tree::gen_proofs_with(8 * levels)`].
    ///
    /// ## Panics
    ///
    /// This method panics if `levels` is *less than* `7`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs();
    ///
    /// assert_eq!(proofs.proofs(), 64);
    /// ```
    ///
    /// [`Tree::gen_proofs_with(8 * levels)`]: `Tree::gen_proofs_with()`
    pub fn gen_proofs(&self) -> Proofs {
        self.gen_proofs_with(8 * self.levels)
    }

    /// Generates a new [`Proofs`] containing `2 * proofs` evenly-distributed, randomly selected
    /// leaves along with all internal nodes required to prove the validity of the tree.
    ///
    /// This method selects the leaves in a random but evenly-distributed manner by seeding a
    /// [`ChaCha20Rng`] instance with the tree's root node, and generating `proofs` numbers in
    /// the range `0..(leaves / proofs)`.
    ///
    /// It is recommended that `proofs` is *at least* 8 times greater than the number of levels in
    /// the tree (as passed to [`Tree::new()`]).
    ///
    /// ## Panics
    ///
    /// This method panics if `proofs` is `0` or *greater than* the number of leaves the tree
    /// contains (`leaves = 2 ^ (levels - 1)`).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs_with(64);
    ///
    /// assert_eq!(proofs.proofs(), 64);
    /// ```
    pub fn gen_proofs_with(&self, proofs: usize) -> Proofs {
        assert!(proofs > 0);
        assert!(proofs <= Tree::leaves(self.levels));

        let mut nodes = BTreeMap::new();
        let mut visited = BTreeSet::new();

        // seed the rng with the root node
        let mut rng = ChaCha20Rng::from_seed(self.nodes[0].into());
        let chunks = Tree::leaves(self.levels) as f64 / proofs as f64;
        let offset = Tree::leaves(self.levels) - 1;

        // randomly select the leaves in an evenly-distributed manner
        for proof in 0..proofs {
            let distribution =
                Uniform::new(chunks * proof as f64, chunks * (proof + 1) as f64 - 1.0);

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
    // ==================================== Constructors ==================================== \\

    /// Creates a new [`Proofs`] instance from a service description, number of levels, number of
    /// proofs and [`BTreeMap`] associating the index of nodes to their hash.
    ///
    /// ## Panics
    ///
    /// This function will panic if `levels` is *less than* `2`, or if `proofs` is `0` or *greater
    /// than* the number of leaves the tree contains (`leaves = 2 ^ (levels - 1)`).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::{Proofs, Tree};
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs_with(64);
    ///
    /// let nodes = proofs.into_nodes();
    /// let proofs = Proofs::new("foobar", 8, 64, nodes);
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn new<Desc: Into<Vec<u8>>>(
        desc: Desc,
        levels: usize,
        proofs: usize,
        nodes: BTreeMap<usize, [u8; 32]>,
    ) -> Self {
        assert!(levels > 1);
        assert!(proofs > 0);
        assert!(proofs <= Tree::leaves(levels));

        Proofs {
            desc: desc.into(),
            levels,
            proofs,
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
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs();
    ///
    /// assert_eq!(proofs.description(), b"foobar");
    /// ```
    pub fn description(&self) -> &[u8] {
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
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs();
    ///
    /// assert_eq!(proofs.levels(), 8);
    /// ```
    pub fn levels(&self) -> usize {
        self.levels
    }

    /// Returns the number of proofs (`leaves / 2`) included in the [`Proofs`] (as passed to
    /// [`Tree::gen_proofs_with()`] or `8 * levels` if [`Tree::gen_proofs()`] was used).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree = Tree::new("foobar", 8);
    /// let proofs = tree.gen_proofs_with(64);
    ///
    /// assert_eq!(proofs.proofs(), 64);
    /// ```
    ///
    /// [`Tree::gen_proofs(_with)?()`]: `Tree::gen_proofs()`
    pub fn proofs(&self) -> usize {
        self.proofs
    }

    /// Returns a reference to a [`BTreeMap`] associating the index of the nodes included in the
    /// [`Proofs`] to their hash.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree_a = Tree::new("foobar", 8);
    /// let proofs_a = tree_a.gen_proofs();
    ///
    /// let tree_b = Tree::new("foobar", 8);
    /// let proofs_b = tree_b.gen_proofs();
    ///
    /// assert_eq!(proofs_a.as_nodes(), proofs_b.as_nodes());
    /// ```
    pub fn as_nodes(&self) -> &BTreeMap<usize, [u8; 32]> {
        &self.nodes
    }

    /// Returns a [`BTreeMap`] associating the index of the nodes included in the [`Proofs`] to
    /// their hash, consuming the `Proofs`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use p0w::Tree;
    ///
    /// let tree_a = Tree::new("foobar", 8);
    /// let proofs_a = tree_a.gen_proofs();
    ///
    /// let tree_b = Tree::new("foobar", 8);
    /// let proofs_b = tree_b.gen_proofs();
    ///
    /// assert_eq!(proofs_a.into_nodes(), proofs_b.into_nodes());
    /// ```
    pub fn into_nodes(self) -> BTreeMap<usize, [u8; 32]> {
        self.nodes
    }

    /// Verifies that the proofs are valid, returning an [`Error`] otherwise.
    ///
    /// This function does the following verification (in order):
    /// - the nodes that are included in the proofs allow to verify the tree
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
    /// let proofs = tree.gen_proofs();
    ///
    /// assert!(proofs.verify().is_ok());
    /// ```
    pub fn verify(&self) -> Result<(), Error> {
        let leaves_offset = Tree::leaves(self.levels) - 1;
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

            if node >= leaves_offset {
                return Err(Error::MissingLeaf(node - leaves_offset));
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
        let service = blake3::hash(&self.desc);
        for (leaf, hash) in self
            .nodes
            .range(leaves_offset..)
            .map(|(node, hash)| ((node - leaves_offset), hash))
        {
            if Hash::from(*hash) != blake3::keyed_hash(service.as_bytes(), &leaf.to_le_bytes()[..])
            {
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
        let chunks = Tree::leaves(self.levels) as f64 / self.proofs as f64;

        // verify that the right leaves were included
        for proof in 0..self.proofs {
            let distribution =
                Uniform::new(chunks * proof as f64, chunks * (proof + 1) as f64 - 1.0);

            let leaf = distribution.sample(&mut rng).ceil() as usize;
            if !self.nodes.contains_key(&(leaf + leaves_offset)) {
                return Err(Error::MissingLeaf(leaf));
            }
        }

        Ok(())
    }
}

// ========================================== impl Into ========================================= \\

impl Into<BTreeMap<usize, [u8; 32]>> for Proofs {
    fn into(self) -> BTreeMap<usize, [u8; 32]> {
        self.nodes
    }
}
