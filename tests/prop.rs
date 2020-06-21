/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use p0w::Tree;
use proptest::prelude::*;

// ========================================== proptest! ========================================= \\

proptest! {
    #[test]
    fn prop_works(
        desc: Vec<u8>,
        (levels, proofs) in (2usize..12).prop_flat_map(|levels| {
            (Just(levels), 1usize..(1 << (levels - 1)))
        }),
    ) {
        let tree = Tree::new(desc, levels);
        let proofs = tree.gen_proofs_with(proofs);
        prop_assert!(proofs.verify().is_ok());
    }

    #[cfg(feature = "rayon")]
    #[test]
    fn prop_par_works(
        desc: Vec<u8>,
        (levels, proofs) in (2usize..12).prop_flat_map(|levels| {
            (Just(levels), 1usize..(1 << (levels - 1)))
        }),
    ) {
        let tree = Tree::par_new(desc, levels);
        let proofs = tree.gen_proofs_with(proofs);
        prop_assert!(proofs.verify().is_ok());
    }
}
