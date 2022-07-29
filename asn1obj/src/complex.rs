
use crate::asn1impl::{Asn1Op};
use std::io::{Write};
use std::error::Error;


use crate::{asn1obj_error_class,asn1obj_new_error};
use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};

use crate::strop::{asn1_format_line};
use crate::base::{asn1obj_extract_header,asn1obj_format_header};

use crate::consts::{ASN1_PRIMITIVE_TAG,ASN1_SEQ_MASK,ASN1_SET_MASK,ASN1_IMP_SET_MASK,ASN1_IMP_FLAG_MASK};

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
pub struct Asn1ImpSet<T : Asn1Op, const TAG:u8=0> {
	pub val : Vec<T>,
	tag : u8,
	data : Vec<u8>,
}



impl<T: Asn1Op, const TAG:u8> Asn1Op for Asn1ImpSet<T,TAG> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_SET_MASK ) != ASN1_IMP_SET_MASK {
			/*we do have any type*/
			return Ok(retv);
		}

		let ctag = (flag as u8) & ASN1_PRIMITIVE_TAG;
		if ctag != self.tag {
			asn1obj_new_error!(Asn1ComplexError,"tag [0x{:02x}] != self.tag [0x{:02x}]", ctag,self.tag)
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

		flag = (ASN1_IMP_SET_MASK | self.tag ) as u64;
		retv = asn1obj_format_header(flag,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.len() == 0 {
			let s = asn1_format_line(tab,&(format!("{} IMP_SET 0",name)));
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
		Asn1ImpSet {
			data : Vec::new(),
			tag : TAG,
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
pub struct Asn1ImpVec<T : Asn1Op,const TAG:u8=0> {
	pub val : Vec<T>,
	tag : u8,
	data : Vec<u8>,
}


impl<T: Asn1Op, const TAG:u8> Asn1Op for Asn1ImpVec<T,TAG> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_SET_MASK) != ASN1_IMP_SET_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_SET_MASK[0x{:02x}] != ASN1_IMP_SET_MASK [0x{:02x}]", flag, ASN1_IMP_SET_MASK,ASN1_IMP_SET_MASK}
		}

		let ctag = code[0] & ASN1_PRIMITIVE_TAG;
		if ctag != self.tag {
			asn1obj_new_error!{Asn1ComplexError,"tag [0x{:02x}] != self.tag [0x{:02x}]", ctag, self.tag}
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
		Asn1ImpVec {
			data : Vec::new(),
			tag : TAG,
			val : Vec::new(),
		}
	}
}

#[derive(Clone)]
pub struct Asn1Imp<T : Asn1Op,const TAG:u8=0> {
	pub val : T,
	tag : u8,
	data : Vec<u8>,
}


impl<T: Asn1Op, const TAG:u8> Asn1Op for Asn1Imp<T,TAG> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		let  mut parsevec : Vec<u8>;
		let encv :Vec<u8>;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_FLAG_MASK) != ASN1_IMP_FLAG_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_FLAG_MASK[0x{:02x}] != ASN1_IMP_FLAG_MASK [0x{:02x}]", flag, ASN1_IMP_FLAG_MASK,ASN1_IMP_FLAG_MASK}
		}

		let ctag = code[0] & ASN1_PRIMITIVE_TAG;
		if ctag != self.tag {
			asn1obj_new_error!{Asn1ComplexError,"tag [0x{:02x}] != self.tag [0x{:02x}]", ctag, self.tag}
		}

		retv += hdrlen;
		encv = self.val.encode_asn1()?;
		if encv.len() < 1 {
			asn1obj_new_error!{Asn1ComplexError,"{} < 1",encv.len()}
		}
		parsevec = Vec::new();
		/*to make first tag*/
		parsevec.push(encv[0]);
		for i in 1..(totallen+hdrlen) {
			parsevec.push(code[i]);
		}

		let _ = self.val.decode_asn1(&parsevec)?;
		retv += totallen;
		self.data = Vec::new();
		for i in 0..retv {
			self.data.push(code[i]);
		}
		asn1obj_log_trace!("retv [{}]",retv);

		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;

		retv = self.val.encode_asn1()?;
		if retv.len() < 1 {
			asn1obj_new_error!{Asn1ComplexError,"{} < 1",retv.len()}
		}

		retv[0] = self.tag | ASN1_IMP_FLAG_MASK;
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let s = asn1_format_line(tab,&format!("{} IMP", name));
		let _ = iowriter.write(s.as_bytes())?;
		let _ = self.val.print_asn1(name,tab,iowriter)?;
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1Imp {
			data : Vec::new(),
			tag : TAG,
			val : T::init_asn1(),
		}
	}
}


#[derive(Clone)]
pub struct Asn1Ndef<T : Asn1Op + Clone, const TAG:u8=0> {
	pub val :Option<T>,
	tag : u8,
	data : Vec<u8>,
}



impl<T: Asn1Op + Clone, const TAG:u8> Asn1Op for Asn1Ndef<T,TAG> {
	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_SET_MASK) != ASN1_IMP_SET_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_SET_MASK[0x{:02x}] != ASN1_IMP_SET_MASK [0x{:02x}]", flag, ASN1_IMP_SET_MASK,ASN1_IMP_SET_MASK}
		}

		let ctag = code[0] & ASN1_PRIMITIVE_TAG;
		if ctag != self.tag {
			asn1obj_new_error!{Asn1ComplexError,"tag [0x{:02x}] != self.tag [0x{:02x}]",ctag,self.tag}
		}
		self.val = None;
		retv = hdrlen;
		if totallen > 0 {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			if c != totallen {
				asn1obj_new_error!{Asn1ComplexError,"c [{}] != totallen [{}]", c, totallen}
			}
			retv += totallen;
			self.val = Some(v.clone());			
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
		let encv :Vec<u8>;
		let flag :u64;

		if self.val.is_some() {
			let v = self.val.as_ref().unwrap().clone();
			encv = v.encode_asn1()?;
		} else {
			let v = T::init_asn1();
			encv = v.encode_asn1()?;
		}


		flag = (ASN1_IMP_SET_MASK | self.tag) as u64;

		retv = asn1obj_format_header(flag,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		if self.val.is_none() {
			let s = asn1_format_line(tab,&(format!("{} NDEF 0",name)));
			iowriter.write(s.as_bytes())?;
		} else {
			let v = self.val.as_ref().unwrap().clone();
			v.print_asn1(name,tab,iowriter)?
		}
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1Ndef {
			data : Vec::new(),
			tag : TAG,
			val : None,
		}
	}
}

