# libzkbob-rs-node

This project was bootstrapped by [create-neon](https://www.npmjs.com/package/create-neon).

## Installing libzkbob-rs-node

Installing libzkbob-rs-node requires a [supported version of Node and Rust](https://github.com/neon-bindings/neon#platform-support).

You can install the project with yarn. In the project directory, run:

```sh
$ yarn install
```

This fully installs the project, including installing any dependencies and running the build.

## Building libzkbob-rs-node

If you have already installed the project and only want to run the build, run:

```sh
$ yarn build
```

This command uses the [cargo-cp-artifact](https://github.com/neon-bindings/cargo-cp-artifact) utility to run the Rust build and copy the built library into `./index.node`.

## Example
```javascript
const zp = require('libzkbob-rs-node');

const tree = new zp.MerkleTree('./treedb');
const storage = new zp.TxStorage('./txdb');

for (let i = 0; i < 100; ++i) {
    storage.add(i, Buffer.alloc(128));
    tree.addHash(i, Buffer.alloc(32));
}

const proof = tree.getProof(50);
console.log('Proof', proof);
```

## Available Scripts

In the project directory, you can run:

### `yarn install`

Installs the project, including running `yarn build`.

### `yarn build`

Builds the Node addon (`index.node`) from source.

### `yarn test`

Runs the unit tests by calling `cargo test`. You can learn more about [adding tests to your Rust code](https://doc.rust-lang.org/book/ch11-01-writing-tests.html) from the [Rust book](https://doc.rust-lang.org/book/).

