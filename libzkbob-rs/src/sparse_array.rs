use std::{convert::TryFrom, marker::PhantomData, ops::RangeInclusive};

use borsh::{BorshDeserialize, BorshSerialize};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_memorydb::InMemory as MemoryDatabase;
#[cfg(feature = "native")]
use kvdb_rocksdb::{Database as NativeDatabase, DatabaseConfig};
#[cfg(feature = "web")]
use kvdb_web::Database as WebDatabase;

/// A persistent sparse array built on top of kvdb
pub struct SparseArray<D: KeyValueDB, T: BorshSerialize + BorshDeserialize> {
    pub db: D,
    _phantom: PhantomData<T>,
}

#[cfg(feature = "web")]
pub type WebSparseArray<T> = SparseArray<WebDatabase, T>;

#[cfg(feature = "native")]
pub type NativeSparseArray<T> = SparseArray<NativeDatabase, T>;

#[cfg(feature = "web")]
impl<T> SparseArray<WebDatabase, T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub async fn new_web(name: &str) -> SparseArray<WebDatabase, T> {
        let db = WebDatabase::open(name.to_owned(), 1).await.unwrap();

        SparseArray {
            db,
            _phantom: Default::default(),
        }
    }
}

#[cfg(feature = "native")]
impl<T> SparseArray<NativeDatabase, T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub fn new_native(
        config: &DatabaseConfig,
        path: &str,
    ) -> std::io::Result<SparseArray<NativeDatabase, T>> {
        let db = NativeDatabase::open(config, path)?;

        Ok(SparseArray {
            db,
            _phantom: Default::default(),
        })
    }
}

impl<T> SparseArray<MemoryDatabase, T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub fn new_test() -> SparseArray<MemoryDatabase, T> {
        let db = kvdb_memorydb::create(1);

        SparseArray {
            db,
            _phantom: Default::default(),
        }
    }
}

impl<D: KeyValueDB, T> SparseArray<D, T>
where
    D: KeyValueDB,
    T: BorshSerialize + BorshDeserialize + 'static,
{
    pub fn new(db: D) -> SparseArray<D, T> {
        SparseArray {
            db,
            _phantom: Default::default(),
        }
    }

    pub fn get(&self, index: u64) -> Option<T> {
        let key = index.to_be_bytes();

        self.db
            .get(0, &key)
            .unwrap()
            .map(|data| T::try_from_slice(data.as_slice()).unwrap())
    }

    pub fn iter(&self) -> SparseArrayIter<T> {
        SparseArrayIter {
            inner: self.db.iter(0),
            _phantom: Default::default(),
        }
    }

    pub fn iter_slice(&self, range: RangeInclusive<u64>) -> impl Iterator<Item = (u64, T)> + '_ {
        self.iter().filter(move |(index, _)| range.contains(index))
    }

    pub fn set(&self, index: u64, data: &T) {
        let mut batch = self.db.transaction();
        self.set_batched(index, data, &mut batch);
        self.db.write(batch).unwrap();
    }

    pub fn remove(&self, index: u64) {
        let mut batch = self.db.transaction();
        let key = index.to_be_bytes();
        batch.delete(0, &key);
        self.db.write(batch).unwrap();
    }

    pub fn remove_from(&self, from_index: u64) {
        let mut batch = self.db.transaction();
        for (index, _) in self.iter() {
            if index >= from_index {
                let key = index.to_be_bytes();
                batch.delete(0, &key);
            }
        }
        self.db.write(batch).unwrap();
    }

    pub fn remove_all(&self) {
        let mut batch = self.db.transaction();
        //batch.delete_prefix(0, &[][..]);
        self.db
            .iter(0)
            .for_each(|(key, _)| {
                batch.delete(0_u32, &key);
            });
        self.db.write(batch).unwrap();
    }

    // FIXME: Crazy inefficient, replace or improve kvdb
    pub fn count(&self) -> usize {
        self.db.iter(0).count()
    }

    pub fn set_multiple<'a, I>(&self, items: I)
    where
        I: IntoIterator<Item = &'a (u64, T)>,
    {
        let mut batch = self.db.transaction();

        for (index, item) in items {
            self.set_batched(*index, item, &mut batch);
        }

        self.db.write(batch).unwrap();
    }

    fn set_batched(&self, index: u64, data: &T, batch: &mut DBTransaction) {
        let key = index.to_be_bytes();
        let data = data.try_to_vec().unwrap();

        batch.put(0, &key, &data);
    }
}

pub struct SparseArrayIter<'a, T: BorshDeserialize> {
    inner: Box<dyn Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T: BorshDeserialize> Iterator for SparseArrayIter<'a, T> {
    type Item = (u64, T);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, value)| {
            let key = TryFrom::try_from(key.as_ref()).unwrap();
            let index = u64::from_be_bytes(key);
            let data = T::try_from_slice(&value).unwrap();

            (index, data)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_array_iter_slice() {
        let a = SparseArray::new_test();
        a.set(1, &1u32);
        a.set(3, &2);
        a.set(412345, &3);

        assert_eq!(a.db.iter(0).count(), 3, "inner");
        assert_eq!(a.iter().count(), 3, "iter");

        assert_eq!(a.iter_slice(0..=412345).count(), 3, "all");
        assert_eq!(a.iter_slice(1..=412345).count(), 3, "from 1");
        assert_eq!(a.iter_slice(2..=412345).count(), 2, "from 2");
        assert_eq!(a.iter_slice(2..=412344).count(), 1, "from 2 except last");
    }

    #[test]
    fn test_sparse_array_remove() {
        let a = SparseArray::new_test();
        a.set(1, &1u32);
        a.set(3, &2);
        a.set(10, &3);
        a.set(20, &4);
        a.set(25, &5);
        a.set(100, &6);
        
        a.remove_from(10);
        assert_eq!(a.iter_slice(0..=100).count(), 2);

        a.remove_all();
        assert_eq!(a.iter_slice(0..=100).count(), 0);
    }
}
