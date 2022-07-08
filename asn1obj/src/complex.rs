
use crate::asn1impl::{Asn1Op};
use std::io::{Write};
use std::error::Error;
use crate::strop::{asn1_format_line};


pub struct Asn1Opt<T : Asn1Op + Clone> {
	val : Option<T>,
	data : Vec<u8>,
}

impl<T: Asn1Op + Clone> Asn1Op for Asn1Opt<T> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut v :T; 
		let mut retv :usize = 0;
		if self.val.is_some() {
 			v = self.val.as_ref().unwrap().clone();
		} else {
			v = T::init_asn1();
		}

		let ores = v.decode_asn1(code);
		if ores.is_err() {
			self.val = None;
			self.data = Vec::new();
		} else {
			self.val = Some(v);
			retv = ores.unwrap();
			self.data = Vec::new();
			for i in 0..retv {
				self.data.push(code[i]);
			}
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		if self.val.is_some() {
			retv = self.val.as_ref().unwrap().encode_asn1()?;
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.is_none() {
			iowriter.write(asn1_format_line(tab,&format!("{}:<Absent>", name)).as_bytes())?;
		} else {
			let v = self.val.as_ref().unwrap();
			v.print_asn1(name,tab,iowriter)?;
		}
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1Opt {
			data : Vec::new(),
			val : None,			
		}
	}
}
