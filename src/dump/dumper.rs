use crate::dump::error::DumpErr;
use crate::dump::packet::Packet;
use crate::dump::packet_source::Source;

pub struct Dumper {
    source: Source,
}

impl Dumper {
    pub fn new_dumper(dev: &str) -> Result<Dumper, DumpErr> {
        let s = Source::new(dev)?;
        return Ok(Dumper {
            source: s,
        });
    }
    pub fn start(&self) {
        let mut chan = self.source.get_chan();
        loop {
            let b = chan.next().unwrap();
            let packet = Packet::from_bytes(b);
            println!("{}", packet.to_string().as_str());
        }
    }
}

