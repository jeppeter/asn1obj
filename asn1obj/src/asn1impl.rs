
use std::io::{Write};
use std::error::Error;
use serde_json;

pub trait Asn1Op {
	fn equal_asn1(&self, other :&Self) -> bool {
		let ores1 = self.encode_asn1();
		let ores2 = other.encode_asn1();
		if ores1.is_err() || ores2.is_err() {
			return false;
		}

		let sdata = ores1.unwrap();
		let odata = ores2.unwrap();
		if sdata.len() != odata.len() {
			return false;
		}

		for idx in 0..sdata.len() {
			if sdata[idx] != odata[idx] {
				return false;
			}
		}
		return true;
	}
	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>>;
	fn encode_asn1(&self) -> Result<Vec<u8>, Box<dyn Error>>;
	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>>;
	fn init_asn1() -> Self;
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>>;
	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>>;
}

pub trait Asn1Selector {
	fn equal_asn1(&self, other :&Self) -> bool {
		let ores1 = self.encode_select();
		let ores2 = other.encode_select();
		if ores1.is_err() || ores2.is_err() {
			return false;
		}

		let sdata = ores1.unwrap();
		let odata = ores2.unwrap();
		if sdata != odata {
			return false;
		}

		let ores1 = self.decode_select();
		let ores2 = other.decode_select();
		if ores1.is_err() || ores2.is_err() {
			return false;
		}

		let sdata = ores1.unwrap();
		let odata = ores2.unwrap();
		if sdata != odata {
			return false;
		}
		return true;
	}
	fn decode_select(&self) -> Result<String,Box<dyn Error>>;
	fn encode_select(&self) -> Result<String,Box<dyn Error>>;
}
