use crate::io::{Read, Seek};

/// Associated types for a lending fallible iterator.
///
/// Separated from [`FsTryIterator`] so that the GAT `Item<'a>` is
/// defined without any method that uses it. This prevents the Rust
/// compiler from requiring `where Self: 'a` on the GAT
/// (rust-lang/rust#87479), which in turn prevents `for<'a>` HRTB
/// bounds (as used in [`walk_dir`](crate::traverse::walk_dir)) from
/// forcing `Self: 'static`.
///
/// Implementors define both `Error` and `Item<'a>` here, then
/// implement [`FsTryIterator`] for the `try_next` method.
pub trait FsTryIteratorType {
    /// The error type.
    type Error;

    /// The item type, which may borrow from `&'a self`.
    type Item<'a>;
}

/// Lending fallible iterator for filesystem operations.
///
/// Uses generic associated types (GATs) so returned items can borrow
/// from `&'a mut self`, matching the lending pattern in fs-ntfs iterators.
/// The reader `R` is bound at the trait level, consistent with `FsReadSeek<R>`.
///
/// The GAT `Item<'a>` is defined in the supertrait [`FsTryIteratorType`]
/// to avoid the `where Self: 'a` + HRTB `'static` forcing issue
/// (rust-lang/rust#87479).
pub trait FsTryIterator<R: Read + Seek>: FsTryIteratorType {
    /// Advances the iterator and returns the next item, or `None` if
    /// exhausted.
    fn try_next<'a>(&'a mut self, r: &mut R) -> Result<Option<Self::Item<'a>>, Self::Error>;
}

/// Extension trait providing terminal operations on [`FsTryIterator`].
///
/// Automatically implemented for all `FsTryIterator` types via blanket
/// impl.
pub trait FsTryIteratorExt<R: Read + Seek>: FsTryIterator<R> {
    /// Counts the number of items remaining in the iterator.
    fn count(&mut self, r: &mut R) -> Result<usize, Self::Error> {
        let mut n = 0;
        while self.try_next(r)?.is_some() {
            n += 1;
        }
        Ok(n)
    }

    /// Applies `f` to each remaining item.
    fn for_each<F>(&mut self, r: &mut R, mut f: F) -> Result<(), Self::Error>
    where
        F: for<'a> FnMut(Self::Item<'a>),
    {
        while let Some(item) = self.try_next(r)? {
            f(item);
        }
        Ok(())
    }

    /// Returns `true` if any remaining item satisfies `predicate`.
    fn any<P>(&mut self, r: &mut R, mut predicate: P) -> Result<bool, Self::Error>
    where
        P: for<'a> FnMut(Self::Item<'a>) -> bool,
    {
        while let Some(item) = self.try_next(r)? {
            if predicate(item) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Finds the first item for which `f` returns `Some(T)`.
    ///
    /// With lending iterators, `find` cannot return the item directly
    /// (items may borrow from `&mut self`). Use continuation-passing
    /// instead.
    fn find_map<F, T>(&mut self, r: &mut R, mut f: F) -> Result<Option<T>, Self::Error>
    where
        F: for<'a> FnMut(Self::Item<'a>) -> Option<T>,
    {
        while let Some(item) = self.try_next(r)? {
            if let Some(result) = f(item) {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }
}

// Blanket impl: every FsTryIterator gets the extension methods.
impl<R, I> FsTryIteratorExt<R> for I
where
    R: Read + Seek,
    I: FsTryIterator<R>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    // A simple owned-item iterator for testing
    struct CountIter {
        current: u32,
        max: u32,
    }

    impl FsTryIteratorType for CountIter {
        type Error = core::convert::Infallible;
        type Item<'a> = u32;
    }

    impl<R: Read + Seek> FsTryIterator<R> for CountIter {
        fn try_next(&mut self, _r: &mut R) -> Result<Option<u32>, Self::Error> {
            if self.current < self.max {
                let val = self.current;
                self.current += 1;
                Ok(Some(val))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn count_ext() {
        let mut iter = CountIter { current: 0, max: 5 };
        let mut dummy = std::io::Cursor::new(vec![]);
        assert_eq!(iter.count(&mut dummy).unwrap(), 5);
    }

    #[test]
    fn any_ext_found() {
        let mut iter = CountIter { current: 0, max: 5 };
        let mut dummy = std::io::Cursor::new(vec![]);
        assert!(iter.any(&mut dummy, |x| x == 3).unwrap());
    }

    #[test]
    fn any_ext_not_found() {
        let mut iter = CountIter { current: 0, max: 5 };
        let mut dummy = std::io::Cursor::new(vec![]);
        assert!(!iter.any(&mut dummy, |x| x == 10).unwrap());
    }

    #[test]
    fn find_map_ext() {
        let mut iter = CountIter { current: 0, max: 5 };
        let mut dummy = std::io::Cursor::new(vec![]);
        let result = iter
            .find_map(&mut dummy, |x| if x == 3 { Some("found") } else { None })
            .unwrap();
        assert_eq!(result, Some("found"));
    }

    #[test]
    fn for_each_ext() {
        let mut iter = CountIter { current: 0, max: 3 };
        let mut dummy = std::io::Cursor::new(vec![]);
        let mut items = std::vec::Vec::new();
        iter.for_each(&mut dummy, |x| items.push(x)).unwrap();
        assert_eq!(items, vec![0, 1, 2]);
    }

    // Verify GATs work for lending iterators
    struct LendingIter {
        data: [u8; 4],
        pos: usize,
    }

    impl FsTryIteratorType for LendingIter {
        type Error = core::convert::Infallible;
        type Item<'a> = &'a [u8];
    }

    impl<R: Read + Seek> FsTryIterator<R> for LendingIter {
        fn try_next<'a>(&'a mut self, _r: &mut R) -> Result<Option<&'a [u8]>, Self::Error> {
            if self.pos < self.data.len() {
                let slice = &self.data[self.pos..self.pos + 1];
                self.pos += 1;
                Ok(Some(slice))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn lending_iterator_compiles_and_works() {
        let mut iter = LendingIter {
            data: [1, 2, 3, 4],
            pos: 0,
        };
        let mut dummy = std::io::Cursor::new(vec![]);
        let count = iter.count(&mut dummy).unwrap();
        assert_eq!(count, 4);
    }
}
