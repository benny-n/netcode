pub fn add(left: usize, right: usize) -> usize {
    left + right
}

mod bytes;
mod consts;
mod crypto;
mod error;
mod server;
mod token;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
