/**************************************************************************************************
 *                                                                                                *
 * This Source Code Form is subject to the terms of the Mozilla Public                            *
 * License, v. 2.0. If a copy of the MPL was not distributed with this                            *
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.                                       *
 *                                                                                                *
 **************************************************************************************************/

// =========================================== Imports ========================================== \\

use p0w::Tree;

// =========================================== #[test] ========================================== \\

#[test]
fn works() {
    let tree = Tree::new("foobar", 10);
    let proofs = tree.proofs(4);
    assert!(proofs.verify().is_ok());
}
