use std::{env, error::Error, fs};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    // omitted: getting command-line arguments, parsing file, disassembling code section

    println!("Mapping {:?} in memory...", input_path);

    // we'll need to hold onto our "mmap::MemoryMap", because dropping them
    // unmaps them!
    let mut mappings = Vec::new();

    // we're only interested in "Load" segments
    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        // note: mmap-ing would fail if the segments weren't aligned on pages,
        // but luckily, that is the case in the file already. That is not a coincidence.
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();
        // `as` is the "cast" operator, and `_` is a placeholder to force rustc
        // to infer the type based on other hints (here, the left-hand-side declaration)
        let addr: *mut u8 = mem_range.start.0 as _;
        // at first, we want the memory area to be writable, so we can copy to it.
        // we'll set the right permissions later
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
            dst.copy_from_slice(&ph.data[..]);
        }

        println!("Adjusting permissions...");
        // the `region` crate and our `delf` crate have two different
        // enums (and bit flags) for protection, so we need to map from
        // delf's to region's.
        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection)?;
        }
        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", file.entry_point);
    pause("jmp")?;
    unsafe {
        // note that we don't have to do pointer arithmetic here,
        // as the entry point is indeed mapped in memory at the right place.
        jmp(file.entry_point.0 as _);
    }

    Ok(())
}