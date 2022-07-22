use std::env;
use std::process::exit;

mod dump;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len()<2{
        println!("usage: {} DEV-NAME",args[0]);
        exit(1);
    }
    let dumper = dump::dumper::Dumper::new_dumper(args[1].as_str()).unwrap();
    dumper.start()
}
