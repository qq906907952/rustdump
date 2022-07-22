use std::cell::{RefCell, RefMut};
use pnet::datalink;
use pnet::datalink::{DataLinkReceiver, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

use crate::dump::error::DumpErr;

pub struct Source {
    dev: String,
    recv_chan: RefCell<Box<dyn DataLinkReceiver>>,
}

impl Source {
    pub fn get_chan(&self) -> RefMut<Box<dyn DataLinkReceiver>> {
        return self.recv_chan.borrow_mut();
    }
    pub fn new<>(dev: &str) -> Result<Source, DumpErr> {
        let interfaces = datalink::interfaces();
        let interface_names_match = |iface: &NetworkInterface| iface.name == dev;

        let nic = match interfaces.into_iter()
            .filter(interface_names_match)
            .next() {
            Some(i) => {
                i
            }
            None => {
                return Err(DumpErr { info: String::from("interface not found") });
            }
        };
        let (_, rx) = match datalink::channel(&nic, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            _ => {
                return Err(DumpErr { info: String::from("create channel fail") });
            }
        };

        return Ok(Source {
            dev: String::from(dev),
            recv_chan: RefCell::new(rx),
        });
    }
}
