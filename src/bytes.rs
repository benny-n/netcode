use std::io;

use byteorder::{ReadBytesExt, WriteBytesExt};

pub trait Bytes: Sized {
    fn write(&self, writer: &mut impl WriteBytesExt) -> Result<(), io::Error>;
    fn read(reader: &mut impl ReadBytesExt) -> Result<Self, io::Error>;
}
