use std::{convert::TryInto, marker::PhantomData, ops::Range};

use kvdb::KeyValueDB;
use kvdb_memorydb::InMemory as MemoryDatabase;
#[cfg(feature = "web")]
use kvdb_web::Database as WebDatabase;
use libzeropool::{
    constants,
    fawkes_crypto::{ff_uint::Num, ff_uint::PrimeField, BorshDeserialize, BorshSerialize},
    native::{
        account::Account, account::Account as NativeAccount, note::Note, note::Note as NativeNote,
        params::PoolParams,
    },
};

use crate::{merkle::MerkleTree, sparse_array::SparseArray};

pub type TxStorage<D, Fr> = SparseArray<D, Transaction<Fr>>;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Debug)]
pub enum Transaction<Fr: PrimeField> {
    Account(NativeAccount<Fr>),
    Note(NativeNote<Fr>),
}

pub struct State<D: KeyValueDB, P: PoolParams> {
    pub tree: MerkleTree<D, P>,
    /// Stores only usable (own) accounts and notes
    pub(crate) txs: TxStorage<D, P::Fr>,
    pub(crate) latest_account: Option<NativeAccount<P::Fr>>,
    pub latest_account_index: Option<u64>,
    /// Latest owned note index
    pub latest_note_index: u64,
    _params: PhantomData<P>,
}

#[cfg(feature = "web")]
impl<P> State<WebDatabase, P>
where
    P: PoolParams,
    P::Fr: 'static,
{
    pub async fn init_web(db_id: String, params: P) -> Self {
        let merkle_db_name = format!("zkb.{}.smt", &db_id);
        let tx_db_name = format!("zkb.{}.txs", &db_id);
        let tree = MerkleTree::new_web(&merkle_db_name, params.clone()).await;
        let txs = TxStorage::new_web(&tx_db_name).await;

        Self::new(tree, txs)
    }
}

impl<P> State<MemoryDatabase, P>
where
    P: PoolParams,
    P::Fr: 'static,
{
    pub fn init_test(params: P) -> Self {
        let tree = MerkleTree::new_test(params);
        let txs = TxStorage::new_test();

        Self::new(tree, txs)
    }
}

impl<D, P> State<D, P>
where
    D: KeyValueDB,
    P: PoolParams,
    P::Fr: 'static,
{
    pub fn new(tree: MerkleTree<D, P>, txs: TxStorage<D, P::Fr>) -> Self {
        // TODO: Cache
        let mut latest_account_index = None;
        let mut latest_note_index = 0;
        let mut latest_account = None;
        for (index, tx) in txs.iter() {
            match tx {
                Transaction::Account(acc) => {
                    if index >= latest_account_index.unwrap_or(0) {
                        latest_account_index = Some(index);
                        latest_account = Some(acc);
                    }
                }
                Transaction::Note(_) => {
                    if index >= latest_note_index {
                        latest_note_index = index;
                    }
                }
            }
        }

        State {
            tree,
            txs,
            latest_account_index,
            latest_note_index,
            latest_account,
            _params: Default::default(),
        }
    }

    /// Add OUT + 1 hashes to the tree
    pub fn add_hashes(&mut self, at_index: u64, hashes: &[Num<P::Fr>]) {
        // FIXME: return an error instead of asserts
        assert_eq!(
            at_index % (constants::OUT as u64 + 1),
            0,
            "index must be divisible by {}",
            constants::OUT + 1
        );

        self.tree.add_hashes(at_index, hashes.iter().copied());
    }

    /// Add hashes, account, and notes to state
    pub fn add_full_tx(
        &mut self,
        at_index: u64,
        hashes: &[Num<P::Fr>],
        account: Option<Account<P::Fr>>,
        notes: &[(u64, Note<P::Fr>)],
    ) {
        self.add_hashes(at_index, hashes);

        if let Some(acc) = account {
            self.add_account(at_index, acc);
        }

        // Store notes
        for (index, note) in notes {
            self.add_note(*index, *note);
        }
    }

    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account<P::Fr>) {
        // Update tx storage
        self.txs.set(at_index, &Transaction::Account(account));

        if at_index >= self.latest_account_index.unwrap_or(0) {
            self.latest_account_index = Some(at_index);
            self.latest_account = Some(account);
        }
    }

    /// Caches a note at specified index.
    pub fn add_note(&mut self, at_index: u64, note: Note<P::Fr>) {
        if self.txs.get(at_index).is_some() {
            return;
        }

        self.txs.set(at_index, &Transaction::Note(note));

        if at_index > self.latest_note_index {
            self.latest_note_index = at_index;
        }
    }

    pub fn get_all_txs(&self) -> Vec<(u64, Transaction<P::Fr>)> {
        self.txs.iter().collect()
    }

    pub fn get_usable_notes(&self) -> Vec<(u64, Note<P::Fr>)> {
        let next_usable_index = self.earliest_usable_index();

        // Fetch all usable notes from the state
        self
        .txs
        .iter_slice(next_usable_index..=self.latest_note_index)
        .filter_map(|(index, tx)| match tx {
            Transaction::Note(note) => Some((index, note)),
            _ => None,
        })
        .collect()
    }

    pub fn get_account(&self, index: u64) -> Option<Account<P::Fr>> {
        match self.txs.get(index) {
            Some(Transaction::Account(acc)) => Some(acc),
            _ => None,
        }
    }

    pub fn get_previous_account(&self, index: u64) -> Option<(u64, Account<P::Fr>)> {
        if index == 0 { return None }

        let prev_acc_indexes = self.txs
            .iter_slice(0..=(index-1))
            .filter_map(|(idx, tx)| match tx {
                Transaction::Account(_) => Some(idx),
                _ => None,
            })
            .max();

        match prev_acc_indexes {
            Some(idx) => Some((idx, self.get_account(idx).unwrap())),
            _ => None,
        }
    }

    pub fn get_notes_in_range(&self, range: Range<u64>) -> Vec<(u64, Note<P::Fr>)> {
        self.txs
            .iter_slice(range.start..=range.end.saturating_sub(1))
            .filter_map(|(idx, tx)| match tx {
                Transaction::Note(note) => Some((idx, note)),
                _ => None,
            })
            .collect()
    }

    /// Return an index of a earliest usable note.
    pub fn earliest_usable_index(&self) -> u64 {
        let latest_account_index = self
            .latest_account
            .map(|acc| acc.i.to_num())
            .unwrap_or(Num::ZERO)
            .try_into()
            .unwrap();

        self.txs
            .iter_slice(latest_account_index..=self.latest_note_index)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(_) => Some(index),
                _ => None,
            })
            .next()
            .unwrap_or(latest_account_index)
    }

    /// Return an index of a earliest usable note including optimistic state
    pub fn earliest_usable_index_optimistic(
        &self,
        optimistic_accounts: &[(u64, Account<P::Fr>)],
        optimistic_notes: &[(u64, Note<P::Fr>)]
    ) -> u64 {
        let latest_account_index = optimistic_accounts
            .last()
            .map(|indexed_acc| indexed_acc.1)
            .or(self.latest_account)
            .map(|acc| acc.i.to_num())
            .unwrap_or(Num::ZERO)
            .try_into()
            .unwrap();

        
        let latest_note_index_optimistic = optimistic_notes
            .last()
            .map(|indexed_note| indexed_note.0)
            .unwrap_or(self.latest_note_index);

        let optimistic_note_indices = optimistic_notes
            .iter()
            .map(|indexed_note| indexed_note.0)
            .filter(move |index| (latest_account_index..=latest_note_index_optimistic).contains(index));

        
        self.txs
            .iter_slice(latest_account_index..=latest_note_index_optimistic)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(_) => Some(index),
                _ => None,
            })
            .chain(optimistic_note_indices)
            .next()
            .unwrap_or(latest_account_index)
    }

    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> Num<P::Fr> {
        self.account_balance() + self.note_balance()
    }

    pub fn account_balance(&self) -> Num<P::Fr> {
        self.latest_account
            .map(|acc| acc.b.to_num())
            .unwrap_or(Num::ZERO)
    }

    pub fn note_balance(&self) -> Num<P::Fr> {
        let starting_index = self
            .latest_account
            .map(|acc| acc.i.to_num().try_into().unwrap())
            .unwrap_or(0);
        let mut note_balance = Num::ZERO;
        for (_, tx) in self.txs.iter_slice(starting_index..=self.latest_note_index) {
            if let Transaction::Note(note) = tx {
                note_balance += note.b.to_num();
            }
        }

        note_balance
    }

    // rollback current state, return updated next_index
    pub fn rollback(&mut self, rollback_index: u64) -> u64 {
        if rollback_index > self.tree.next_index() {
            return self.tree.next_index();
        }

        let rollback_index = (rollback_index >> constants::OUTPLUSONELOG) << constants::OUTPLUSONELOG;
        self.txs.remove_from(rollback_index);
        self.latest_account = None;
        self.latest_account_index = None;
        self.latest_note_index = 0;
        for (index, tx) in self.txs.iter() {
            match tx {
                Transaction::Account(acc) => {
                    if index >= self.latest_account_index.unwrap_or(0) {
                        self.latest_account_index = Some(index);
                        self.latest_account = Some(acc);
                    }
                }
                Transaction::Note(_) => {
                    if index >= self.latest_note_index {
                        self.latest_note_index = index;
                    }
                }
            }
        }

        if self.tree.rollback(rollback_index).is_none() {
            self.wipe();
        }

        self.tree.next_index()
    }

    pub fn wipe(&mut self) {
        self.tree.wipe();

        self.txs.remove_all();
        self.latest_account_index = None;
        self.latest_account = None;
        self.latest_note_index = 0;
    }

}
