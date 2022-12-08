const zp = require('./index.js')

let tree = new zp.MerkleTree('./testdb');

console.log(`Root at index ${tree.getNextIndex()}: ${tree.getRoot()}`);

console.log('Building the tree...');
for (let i = 0; i < 512; ++i) {;
    tree.addHash(i, Buffer.alloc(32).fill(i % 10));
}

console.log('Calculating proof...')
let proof = tree.getProof(50);
console.log('Proof', proof);

let fixed_index = tree.getNextIndex();
console.log(`Root at index ${tree.getNextIndex()}: ${tree.getRoot()}`);
tree.setLastStableIndex(fixed_index);

console.log('Appending hashes...');
for (let i = 0; i < 256; ++i) {
    tree.addHash(i + fixed_index, Buffer.alloc(32).fill(i % 20));
}

const siblingsIndex = 640;
console.log(`Getting siblings at index ${siblingsIndex} ...`);
try {
    let siblings = tree.getLeftSiblings(siblingsIndex);
    console.log(siblings);
} catch(err) {
    console.error(`Cannot get siblings: ${err}`);
}

console.log(`Root at index ${tree.getNextIndex()}: ${tree.getRoot()}`);

console.log(`Rollback tree to the index ${fixed_index}...`);
tree.rollback(tree.getLastStableIndex());

console.log(`Root at index ${tree.getNextIndex()}: ${tree.getRoot()}`);

console.log(`Wipe Merkle tree...`);
tree.wipe();

console.log(`Root at index ${tree.getNextIndex()}: ${tree.getRoot()}`);




