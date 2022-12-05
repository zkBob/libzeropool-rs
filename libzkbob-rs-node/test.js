const zp = require('./index.js')

let tree = new zp.MerkleTree('./testdb');

console.log('Building the tree...');
for (let i = 0; i < 512; ++i) {
    tree.addHash(i, Buffer.alloc(32));
}

console.log('Calculating proof...')
let proof = tree.getProof(50);
console.log('Proof', proof);

console.log('Getting siblings...')
try {
    let siblings = tree.getLeftSiblings(111);
    console.log(siblings);
} catch(err) {
    console.error(`Cannot get siblings: ${err}`);
}