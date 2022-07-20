
use std::io::{Write};
use std::error::Error;

pub trait Asn1Op {
	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>>;
	fn encode_asn1(&self) -> Result<Vec<u8>, Box<dyn Error>>;
	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>>;
	fn init_asn1() -> Self;
}

pub trait Asn1TagOp {
	fn set_tag(&mut self, tag :u8) -> Result<u8,Box<dyn Error>>;
	fn get_tag(&self) -> u8;
}