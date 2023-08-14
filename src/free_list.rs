// pub struct FreeList<T: Sized, const N: usize> {
//     len: usize,
//     inner: [Option<T>; N],
// }

// impl<T: Sized, const N: usize> FreeList<T, N> {
//     const INIT: Option<T> = None;
//     pub fn new() -> Self {
//         Self {
//             len: 0,
//             inner: [Self::INIT; N],
//         }
//     }
// }

// impl<T: Sized, const N: usize> FreeList<T, N> {
//     pub fn len(&self) -> usize {
//         self.len
//     }
//     pub fn insert(&mut self, index: usize, value: T) {
//         if self.inner[index].is_none() {
//             self.len += 1;
//         }
//         self.inner[index] = Some(value);
//     }

//     pub fn remove(&mut self, index: usize) {
//         if self.inner[index].is_some() {
//             self.len -= 1;
//         }
//         self.inner[index] = None;
//     }

//     pub fn get(&self, index: usize) -> Option<&T> {
//         self.inner.get(index).and_then(Option::as_ref)
//     }

//     pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
//         self.inner.get_mut(index).and_then(Option::as_mut)
//     }
// }

// impl<T: Sized, const N: usize> std::ops::Index<usize> for FreeList<T, N> {
//     type Output = T;

//     fn index(&self, index: usize) -> &Self::Output {
//         self.get(index).expect("index out of bounds")
//     }
// }

// impl<T: Sized, const N: usize> std::ops::IndexMut<usize> for FreeList<T, N> {
//     fn index_mut(&mut self, index: usize) -> &mut Self::Output {
//         self.get_mut(index).expect("index out of bounds")
//     }
// }
