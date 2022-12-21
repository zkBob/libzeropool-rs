const zp = require('./index.node');

class MerkleTree {
    constructor(path) {
        this.inner = zp.merkleNew(path);
    }

    getRoot() {
        return zp.merkleGetRoot(this.inner)
    }

    getNextIndex() {
        return zp.merkleGetNextIndex(this.inner)
    }

    getNode(height, index) {
        return zp.merkleGetNode(this.inner, height, index)
    }

    addHash(index, hash) {
        zp.merkleAddHash(this.inner, index, hash);
    }

    addCommitment(index, hash) {
        zp.merkleAddCommitment(this.inner, index, hash)
    }

    appendHash(hash) {
        return zp.merkleAppendHash(this.inner, hash);
    }

    getProof(index) {
        return zp.merkleGetProof(this.inner, index);
    }

    getCommitmentProof(index) {
        return zp.merkleGetCommitmentProof(this.inner, index)
    }

    getAllNodes() {
        return zp.merkleGetAllNodes(this.inner)
    }

    getVirtualNode(
        height,
        index,
        virtual_nodes,
        new_hashes_left_index,
        new_hashes_right_index,
    ) {
        return zp.merkleGetVirtualNode(
            this.inner,
            height,
            index,
            virtual_nodes,
            new_hashes_left_index,
            new_hashes_right_index,
        )
    }

    rollback(index) {
        return zp.merkleRollback(this.inner, index)
    }

    wipe() {
        zp.merkleWipe(this.inner)
    }

    getLeftSiblings(index) {
        return zp.merkleGetLeftSiblings(this.inner, index)
    }

    getLastStableIndex() {
        return zp.merkleGetLastStableIndex(this.inner)
    }

    setLastStableIndex(index) {
        zp.merkleSetLastStableIndex(this.inner, index)
    };

    getRootAt(index) {
        return zp.merkleGetRootAt(this.inner, index)
    }
}

class TxStorage {
    constructor(path) {
        this.inner = zp.txStorageNew(path);
    }

    add(index, data) {
        zp.txStorageAdd(this.inner, index, data);
    }

    get(index) {
        return zp.txStorageGet(this.inner, index);
    }

    delete(index) {
        return zp.txStorageDelete(this.inner, index);
    }

    count() {
        return zp.txStorageCount(this.inner);
    }
}

const Params = {
    fromBinary: zp.readParamsFromBinary,
    fromFile: zp.readParamsFromFile,
};

const Proof = {
    tx: zp.proveTx,
    tree: zp.proveTree,
    txAsync: zp.proveTxAsync,
    treeAsync: zp.proveTreeAsync,
    verify: zp.verify,
};

class Helpers {
    static outCommitmentHash(outHashes) {
        return zp.helpersOutCommitment(outHashes)
    }

    static parseDelta(delta) {
        return zp.helpersParseDelta(delta)
    }

    static numToStr(num) {
        return zp.helpersNumToStr(num)
    }

    static strToNum(str) {
        return zp.helpersStrToNum(str)
    }
}

zp.MerkleTree = MerkleTree;
zp.TxStorage = TxStorage;
zp.Params = Params;
zp.Proof = Proof
zp.Helpers = Helpers;
module.exports = zp;
