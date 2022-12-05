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
    let siblings = tree.getLeftSiblings(384);
    console.log(siblings);
    console.log('Node = ', tree.getNode(7, 2));
} catch(err) {
    console.error(`Cannot get siblings: ${err}`);
}