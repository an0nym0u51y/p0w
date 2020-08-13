# Merkle tree Proof-of-Work (PoW)

[![img](https://img.shields.io/crates/l/p0w.svg)](https://github.com/r3v2d0g/p0w/blob/main/LICENSE.txt) [![img](https://img.shields.io/crates/v/p0w.svg)](https://crates.io/crates/p0w) [![img](https://docs.rs/p0w/badge.svg)](https://docs.rs/p0w)

This crate provides an implementation of the [following paper](https://hal-mines-paristech.archives-ouvertes.fr/hal-00752925/):

> Fabien Coelho. An (Almost) Constant-E ort Solution-Veri cation Proof-of-Work Protocol based on Merkle Trees. 1st international conference on Progress in cryptology, Jun 2008, Casablanca, Morocco. pp.Pages 80-93. ⟨hal-00752925⟩


## How does it work?

`Tree::new()` creates a new Merkle tree with a specified service description and number of levels, in which leaves are equal to `hmac(h(desc), leaf)` (with `desc` the service description, and `leaf` the zero-based index of the leaf).

`Tree::proofs()` then creates a `Proofs` for the tree with a specified number of evenly-distributed, randomly selected leaves, their sibling and the internal nodes required to prove the validity of the tree up to its root node.


## Example

```rust
use p0w::Tree;

let tree = Tree::new("foobar", 16);
let proofs = tree.proofs(4);

assert!(proofs.verify().is_ok());
```


## License

> This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain one at <http://mozilla.org/MPL/2.0/>.
