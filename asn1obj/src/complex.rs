
use crate::asn1impl::{Asn1Op,Asn1TagOp};
use std::io::{Write};
use std::error::Error;


use crate::{asn1obj_error_class,asn1obj_new_error};
use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};

use crate::strop::{asn1_format_line};
use crate::base::{asn1obj_extract_header,asn1obj_format_header};

use crate::consts::{ASN1_SET_OF_FLAG,ASN1_PRIMITIVE_TAG,ASN1_SEQ_MASK,ASN1_SET_MASK,ASN1_IMP_SET_MASK};

asn1obj_error_class!{Asn1ComplexError}

#[derive(Clone)]
pub struct Asn1Opt<T : Asn1Op + Clone> {
	pub val : Option<T>,
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

#[derive(Clone)]
pub struct Asn1SetOf<T : Asn1Op> {
	pub val : Vec<T>,
	tag : u8,
	data : Vec<u8>,
}

impl<T :Asn1Op> Asn1TagOp for Asn1SetOf<T> {
	fn set_tag(&mut self, tag :u8) -> Result<u8,Box<dyn Error>> {
		let oldtag :u8;
		if (tag & ASN1_PRIMITIVE_TAG) != tag {
			asn1obj_new_error!{Asn1ComplexError,"can not accept tag [0x{:02x}] in ASN1_PRIMITIVE_TAG [0x{:02x}]", tag,ASN1_PRIMITIVE_TAG}
		}
		oldtag = self.tag;
		self.tag = tag;
		Ok(oldtag)
	}

	fn get_tag(&self) -> u8 {
		return self.tag;
	}
}


impl<T: Asn1Op> Asn1Op for Asn1SetOf<T> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_SET_OF_FLAG ) != ASN1_SET_OF_FLAG {
			/*we do have any type*/
			return Ok(retv);
		}

		self.tag = (flag as u8) & ASN1_PRIMITIVE_TAG;

		retv += hdrlen;
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			retv += c;
			self.val.push(v);
		}

		self.data = Vec::new();
		for i in 0..retv {
			self.data.push(code[i]);
		}
		asn1obj_log_trace!("retv [{}]",retv);

		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		let mut encv :Vec<u8> = Vec::new();
		let mut idx :usize = 0;
		let flag :u64;


		if self.val.len() == 0{
			return Ok(retv);
		}
		while idx < self.val.len() {
			let code = self.val[idx].encode_asn1()?;
			for i in 0..code.len() {
				encv.push(code[i]);
			}
			idx += 1;
		}

		flag = (ASN1_SET_OF_FLAG | self.tag ) as u64;
		retv = asn1obj_format_header(flag,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.len() == 0 {
			let s = asn1_format_line(tab,&(format!("{} SET_OF 0",name)));
			iowriter.write(s.as_bytes())?;
		} else {
			let mut idx :usize = 0;
			while idx < self.val.len() {
				let s = format!("{}[{}]",name,idx);
				let _ = self.val[idx].print_asn1(&s,tab,iowriter)?;
				idx += 1;
			}
		}
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1SetOf {
			data : Vec::new(),
			tag : 0,
			val : Vec::new(),
		}
	}
}

#[derive(Clone)]
pub struct Asn1Seq<T : Asn1Op> {
	pub val : Vec<T>,
	data : Vec<u8>,
}



impl<T: Asn1Op> Asn1Op for Asn1Seq<T> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if (flag as u8) != ASN1_SEQ_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] != ASN1_SEQ_MASK [0x{:02x}]", flag, ASN1_SEQ_MASK}
		}

		retv += hdrlen;
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			retv += c;
			self.val.push(v);
		}

		self.data = Vec::new();
		for i in 0..retv {
			self.data.push(code[i]);
		}
		asn1obj_log_trace!("retv [{}]",retv);

		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;
		let mut encv :Vec<u8> = Vec::new();
		let mut idx :usize = 0;


		while idx < self.val.len() {
			let code = self.val[idx].encode_asn1()?;
			for i in 0..code.len() {
				encv.push(code[i]);
			}
			idx += 1;
		}

		retv = asn1obj_format_header(ASN1_SEQ_MASK as u64,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.len() == 0 {
			let s = asn1_format_line(tab,&(format!("{} SEQ 0",name)));
			iowriter.write(s.as_bytes())?;
		} else {
			let mut idx :usize = 0;
			while idx < self.val.len() {
				let s = format!("{}[{}]",name,idx);
				let _ = self.val[idx].print_asn1(&s,tab,iowriter)?;
				idx += 1;
			}
		}
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1Seq {
			data : Vec::new(),
			val : Vec::new(),
		}
	}
}

#[derive(Clone)]
pub struct Asn1Set<T : Asn1Op> {
	pub val : Vec<T>,
	data : Vec<u8>,
}

impl<T: Asn1Op> Asn1Op for Asn1Set<T> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if (flag as u8) != ASN1_SET_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] != ASN1_SET_MASK [0x{:02x}]", flag, ASN1_SET_MASK}
		}

		retv += hdrlen;
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			retv += c;
			self.val.push(v);
		}

		self.data = Vec::new();
		for i in 0..retv {
			self.data.push(code[i]);
		}
		asn1obj_log_trace!("retv [{}]",retv);

		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;
		let mut encv :Vec<u8> = Vec::new();
		let mut idx :usize = 0;


		while idx < self.val.len() {
			let code = self.val[idx].encode_asn1()?;
			for i in 0..code.len() {
				encv.push(code[i]);
			}
			idx += 1;
		}

		retv = asn1obj_format_header(ASN1_SET_MASK as u64,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.len() == 0 {
			let s = asn1_format_line(tab,&(format!("{} SET 0",name)));
			iowriter.write(s.as_bytes())?;
		} else {
			let mut idx :usize = 0;
			while idx < self.val.len() {
				let s = format!("{}[{}]",name,idx);
				let _ = self.val[idx].print_asn1(&s,tab,iowriter)?;
				idx += 1;
			}
		}
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1Set {
			data : Vec::new(),
			val : Vec::new(),
		}
	}
}

#[derive(Clone)]
pub struct Asn1ImpEncap<T : Asn1Op> {
	pub val : Vec<T>,
	tag : u8,
	data : Vec<u8>,
}


impl<T: Asn1Op> Asn1TagOp for Asn1ImpEncap<T> {
	fn set_tag(&mut self, tag :u8) -> Result<u8,Box<dyn Error>> {
		let oldtag :u8;
		if (tag & ASN1_PRIMITIVE_TAG) != tag {
			asn1obj_new_error!{Asn1ComplexError,"can not accept tag [0x{:02x}] in ASN1_PRIMITIVE_TAG [0x{:02x}]", tag,ASN1_PRIMITIVE_TAG}
		}
		oldtag = self.tag;
		self.tag = tag;
		Ok(oldtag)
	}

	fn get_tag(&self) -> u8 {
		return self.tag;
	}	
}

impl<T: Asn1Op> Asn1Op for Asn1ImpEncap<T> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_SET_MASK) != ASN1_IMP_SET_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_SET_MASK[0x{:02x}] != ASN1_IMP_SET_MASK [0x{:02x}]", flag, ASN1_IMP_SET_MASK,ASN1_IMP_SET_MASK}
		}

		let _ = self.set_tag(code[0] & ASN1_PRIMITIVE_TAG)?;

		retv += hdrlen;
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			retv += c;
			self.val.push(v);
		}

		self.data = Vec::new();
		for i in 0..retv {
			self.data.push(code[i]);
		}
		asn1obj_log_trace!("retv [{}]",retv);

		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;
		let mut encv :Vec<u8> = Vec::new();
		let mut idx :usize = 0;
		let flag :u64;


		while idx < self.val.len() {
			let code = self.val[idx].encode_asn1()?;
			for i in 0..code.len() {
				encv.push(code[i]);
			}
			idx += 1;
		}

		flag = (ASN1_IMP_SET_MASK | self.tag) as u64;

		retv = asn1obj_format_header(flag,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.len() == 0 {
			let s = asn1_format_line(tab,&(format!("{} IMP_ENCAP 0",name)));
			iowriter.write(s.as_bytes())?;
		} else {
			let mut idx :usize = 0;
			while idx < self.val.len() {
				let s = format!("{}[{}]",name,idx);
				let _ = self.val[idx].print_asn1(&s,tab,iowriter)?;
				idx += 1;
			}
		}
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1ImpEncap {
			data : Vec::new(),
			tag : 0,
			val : Vec::new(),
		}
	}
}