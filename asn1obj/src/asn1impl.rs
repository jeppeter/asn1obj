
use std::io::{Write};
use std::error::Error;
use serde_json;

pub trait Asn1Op {
	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>>;
	fn encode_asn1(&self) -> Result<Vec<u8>, Box<dyn Error>>;
	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>>;
	fn init_asn1() -> Self;
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>>;
	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>>;
}

pub trait Asn1Selector {
	fn decode_select(&self) -> Result<String,Box<dyn Error>>;
	fn encode_select(&self) -> Result<String,Box<dyn Error>>;
}
