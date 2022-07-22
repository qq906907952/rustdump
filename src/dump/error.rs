use std::fmt::{Debug, Display, Formatter};

pub struct DumpErr {
    pub info: String,
}


impl Display for DumpErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.info.as_str());
        return Ok(());
    }
}

impl Debug for DumpErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.info.as_str());
        return Ok(());
    }
}

