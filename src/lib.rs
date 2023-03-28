mod parse;

use derive_try_from_primitive::TryFromPrimitive;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);

impl_parse_for_enum!(SegmentFlag, le_u32);

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
}

use std::ops::Range;

impl ProgramHeader {
    /**
     * File range where the segment is stored
     */
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /**
     * Memory range where the segment is mapped
     */
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            // the default Debug formatter for `enumflags2` is a bit
            // on the verbose side, let's print something like `RWX` instead
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X")
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.r#type,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

 
 impl_parse_for_enum!(SegmentType, le_u32);

 #[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl Machine {
    /* pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            combinator::map_res,
            error::{context, ErrorKind},
            number::complete::le_u16,
        };
        context(
            "Machine",
            map_res(le_u16, |x| Self::try_from(x).map_err(|_| ErrorKind::Alt)),
        )(i)
    } */
}

impl Type {
    fn to_u16(&self) -> u16 {
        match self {
            Self::None => 0,
            Self::Rel => 1,
            Self::Exec => 2,
            Self::Dyn => 3,
            Self::Core => 4
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn try_bitflag() {
        use super::SegmentFlag;
        use enumflags2::BitFlags;

        // this is a value we could've read straight from an ELF file
        let flags_integer: u32 = 6;
        // this is how we parse it. in practice, it's less verbose,
        // because of type inference.
        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();
        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        // this does not correspond to any flags
        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}


#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub program_headers: Vec<ProgramHeader>,
}

pub struct HexDump<'a>(&'a [u8]);

use std::fmt;
impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}

use std::convert::TryFrom;

impl File {
    // omitted: magic constant
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    #[allow(unused_variables)]
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let full_input = i;
        use nom::{
            bytes::complete::{tag, take},
            error::context,
            sequence::tuple,
            combinator::map,
            number::complete::le_u16,
        };
        // omitted: parse magic, etc.

        use nom::{combinator::map, number::complete::le_u16};
        // some values are stored as u16 to save storage, but they're actually
        // file offsets, or counts, so we want them as `usize` in rust.
        let u16_usize = map(le_u16, |x| x as usize);

        // ph = program header, sh = section header
        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) = tuple((&u16_usize, &u16_usize))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((&u16_usize, &u16_usize, &u16_usize))(i)?;

        // `chunks()` divides a slice into chunks of equal size - perfect, as we know the entry size.
        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        let res = Self {
            machine,
            r#type,
            entry_point,
            program_headers,
        };
        Ok((i, res))
    }
}


impl File {
    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {
                    // new!
                    use nom::Offset;
                    let offset = i.offset(input);
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }
}

impl ProgramHeader {
    fn parse<'a>(full_input: parse::Input<'_>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::sequence::tuple;
        let (i, (r#type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;

        let ap = Addr::parse;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((ap, ap, ap, ap, ap, ap))(i)?;

        let res = Self {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            // `to_vec()` turns a slice into an owned Vec (this works because u8 is Clone+Copy)
            data: full_input[offset.into()..][..filesz.into()].to_vec(),
        };
        Ok((i, res))
    }
}

use derive_more::*;

// "Add" and "Sub" are in `derive_more`
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// This will come in handy when serializing
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

// This will come in handy when indexing / sub-slicing slices
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

// This will come in handy when parsing
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }
}