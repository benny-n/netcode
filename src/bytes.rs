use std::io;

use byteorder::{ReadBytesExt, WriteBytesExt};

pub trait Bytes: Sized {
    const SIZE: usize = std::mem::size_of::<Self>();
    fn write_to(&self, writer: &mut impl WriteBytesExt) -> Result<(), io::Error>;
    fn read_from(reader: &mut impl ReadBytesExt) -> Result<Self, io::Error>;
}
