
use crate::asn1impl::{Asn1Op,Asn1Selector};
use std::io::{Write};
use std::error::Error;


use crate::{asn1obj_error_class,asn1obj_new_error,asn1obj_debug_buffer_trace,asn1obj_format_buffer_log};
use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};

use crate::strop::{asn1_format_line};
use crate::base::{asn1obj_extract_header,asn1obj_format_header};

use crate::consts::*;

asn1obj_error_class!{Asn1ComplexError}

#[derive(Clone)]
pub struct Asn1Opt<T : Asn1Op + Clone> {
	pub val : Option<T>,
	data : Vec<u8>,
}


impl<T: Asn1Op + Clone> Asn1Op for Asn1Opt<T> {
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		if self.val.is_none() {
			return Ok(0);
		}
		let v :T;
		v = self.val.as_ref().unwrap().clone();
		let _ = v.encode_json(key,val)?;
		return Ok(1);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		if key.len() > 0 {
			let k = val.get(key);
			if k.is_none() {
				self.val = None;
				return Ok(0);
			}			
		}
		let mut v :T = T::init_asn1();
		let _ = v.decode_json(key,val)?;
		self.val = Some(v.clone());
		return Ok(1);
	}

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
			let e = ores.err().unwrap();
			if code.len() > 20 {
				asn1obj_debug_buffer_trace!(code.as_ptr(),20,"Asn1Opt decode [{}:0x{:x}] error[{:?}]", code.len(),code.len(),e);
			} else {
				asn1obj_debug_buffer_trace!(code.as_ptr(),code.len(),"Asn1Opt decode [{}:0x{:x}] error[{:?}]", code.len(),code.len(),e);
			}
			
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
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		let mut mainv :Vec<serde_json::value::Value> = serde_json::from_str("[]").unwrap();
		let mut idx :i32 = 0;
		for v in &self.val {
			let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
			let _ = v.encode_json("", &mut cv)?;
			mainv.push(cv.clone());
			idx += 1;			
		}
		if key.len() > 0 {
			val[key] = serde_json::json!(mainv);	
		} else {
			*val = serde_json::json!(mainv.clone());
		}
		return Ok(idx);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		let mainv :serde_json::value::Value;
		let ck :serde_json::value::Value;
		let mut idx :i32 = 0;
		if key.len() > 0 {
			let k = val.get(key);
			if k.is_none() {
				self.val = Vec::new();
				return Ok(0);
			}
			ck = serde_json::json!(k.unwrap());
		} else {
			ck = val.clone();
		}
		self.val = Vec::new();
		if ck.is_object() {	
			mainv = serde_json::json!(ck.as_object().unwrap().clone());
			let mut t = T::init_asn1();
			let _ = t.decode_json("",&mainv)?;
			self.val.push(t);
			idx += 1;
		} else if ck.is_array() {
			let b = ck.as_array().unwrap();
			for v in b.iter() {				
				let mut t = T::init_asn1();
				let _ = t.decode_json("",v)?;
				self.val.push(t);
				idx += 1;
			}
		} else {
			asn1obj_new_error!{Asn1ComplexError,"{} not valid type",key}
		}
		return Ok(idx);
	}

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

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
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
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		let mut mainv :Vec<serde_json::value::Value> = serde_json::from_str("[]").unwrap();
		let mut idx :i32 = 0;
		for v in &self.val {
			let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
			let _ = v.encode_json("", &mut cv)?;
			mainv.push(cv.clone());
			idx += 1;			
		}
		if key.len() > 0 {
			val[key] = serde_json::json!(mainv);	
		} else {
			*val = serde_json::json!(mainv);
		}
		
		return Ok(idx);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		let ck :serde_json::value::Value;
		let mut idx :i32 = 0;
		if key.len() > 0 {
			let k = val.get(key);
			if k.is_none() {
				self.val = Vec::new();
				return Ok(0);
			}
			ck = serde_json::json!(k.unwrap());
		} else {
			ck = val.clone();
		}
		self.val = Vec::new();
		if ck.is_array() {
			let b = ck.as_array().unwrap();
			for v in b.iter() {
				let mut t = T::init_asn1();
				let _ = t.decode_json("",v)?;
				self.val.push(t);
				idx += 1;
			}			
		} else {
			let mut t = T::init_asn1();
			let _ = t.decode_json("",&ck)?;
			self.val.push(t);
			idx += 1;
		}
		return Ok(idx);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if (flag as u8) != ASN1_SEQ_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] != ASN1_SEQ_MASK [0x{:02x}]", flag, ASN1_SEQ_MASK}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
		}


		retv += hdrlen;
		asn1obj_log_trace!("totallen {}",totallen);
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			asn1obj_log_trace!("c [{}]",c);
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

impl<T: Asn1Op> Asn1Seq<T> {
	pub fn make_safe_one(&mut self,note :&str) -> Result<(),Box<dyn Error>> {
		if self.val.len() != 0 && self.val.len() != 1 {
			asn1obj_new_error!{Asn1ComplexError,"{} len {} != 1 or 0",note,self.val.len()}
		}
		if self.val.len() == 0 {
			self.val.push(T::init_asn1());
		}
		Ok(())
	}

	pub fn check_safe_one(&self,note :&str) -> Result<(),Box<dyn Error>> {
		if self.val.len() != 1 {
			asn1obj_new_error!{Asn1ComplexError,"{} len {} != 1",note,self.val.len()}
		}
		Ok(())
	}

	pub fn sure_safe_one(&self, note :&str) -> Result<(),Box<dyn Error>> {
		if self.val.len() != 1 {
			asn1obj_new_error!{Asn1ComplexError,"{} len {} != 1",note,self.val.len()}
		}
		Ok(())
	}
}

#[derive(Clone)]
pub struct Asn1Set<T : Asn1Op> {
	pub val : Vec<T>,
	data : Vec<u8>,
}

impl<T: Asn1Op> Asn1Op for Asn1Set<T> {
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		let mut mainv : Vec<serde_json::value::Value> = serde_json::from_str("[]").unwrap();
		let mut idx :i32 = 0;
		for v in &self.val {
			let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
			let _ = v.encode_json(ASN1_JSON_DUMMY, &mut cv)?;
			mainv.push(cv[ASN1_JSON_DUMMY].clone());
			idx += 1;			
		}
		if key.len() > 0 {
			val[key] = serde_json::json!(mainv);	
		} else {
			*val = serde_json::json!(mainv);
		}		
		return Ok(idx);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		let mut idx :i32 = 0;
		let ck :serde_json::value::Value;
		if key.len() > 0 {
			let k = val.get(key);
			if k.is_none() {
				self.val = Vec::new();
				return Ok(0);
			}
			ck = serde_json::json!(k.unwrap());
		} else {
			ck = val.clone();
		}
		self.val = Vec::new();
		if ck.is_array() {
			let b = ck.as_array().unwrap();
			for v in b.iter() {
				let mut t = T::init_asn1();
				let _ = t.decode_json("",v)?;
				self.val.push(t);
				idx += 1;
			}
		} else {
			let mut t = T::init_asn1();
			let _ = t.decode_json("",&ck)?;
			self.val.push(t);
			idx += 1;
		}
		return Ok(idx);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		self.val = Vec::new();
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if (flag as u8) != ASN1_SET_MASK {
			/*we do have any type*/
			if code.len() > 32 {
				asn1obj_debug_buffer_trace!(code.as_ptr(),32,"not match len [{}:0x{:x}]",code.len(),code.len());
			} else {
				asn1obj_debug_buffer_trace!(code.as_ptr(),code.len(),"not match len");	
			}
			
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] != ASN1_SET_MASK [0x{:02x}]", flag, ASN1_SET_MASK}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
		}

		retv += hdrlen;
		asn1obj_log_trace!("totallen [{}]", totallen);
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			asn1obj_log_trace!("passed [{}]", c);
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
pub struct Asn1Imp<T : Asn1Op,const TAG:u8=0> {
	pub val : T,
	tag : u8,
	data : Vec<u8>,
}


impl<T: Asn1Op, const TAG:u8> Asn1Op for Asn1Imp<T,TAG> {
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.encode_json(key,val);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.decode_json(key,val);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		let  mut parsevec : Vec<u8>;
		let encv :Vec<u8>;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_FILTER_MASK) != ASN1_IMP_FLAG_MASK {
			/*we do have any type*/
			asn1obj_log_trace!("flag [0x{:02x}] & ASN1_IMP_FILTER_MASK[0x{:02x}] != ASN1_IMP_FLAG_MASK [0x{:02x}]", flag, ASN1_IMP_FILTER_MASK,ASN1_IMP_FLAG_MASK);
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_FILTER_MASK[0x{:02x}] != ASN1_IMP_FLAG_MASK [0x{:02x}]", flag, ASN1_IMP_FILTER_MASK,ASN1_IMP_FLAG_MASK}
		}

		let ctag = code[0] & ASN1_PRIMITIVE_TAG;
		if ctag != self.tag {
			asn1obj_log_trace!("tag [0x{:02x}] != self.tag [0x{:02x}]", ctag, self.tag);
			asn1obj_new_error!{Asn1ComplexError,"tag [0x{:02x}] != self.tag [0x{:02x}]", ctag, self.tag}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
		}


		asn1obj_debug_buffer_trace!(code.as_ptr(),hdrlen + totallen,"will add decode_asn1");
		retv += hdrlen;
		encv = self.val.encode_asn1()?;
		if encv.len() < 1 {
			asn1obj_log_trace!("{} < 1",encv.len());
			asn1obj_new_error!{Asn1ComplexError,"{} < 1",encv.len()}
		}
		asn1obj_debug_buffer_trace!(encv.as_ptr(),encv.len(),"encv value");
		parsevec = Vec::new();
		/*to make first tag*/
		parsevec.push(encv[0]);
		for i in 1..(totallen+hdrlen) {
			parsevec.push(code[i]);
		}

		asn1obj_debug_buffer_trace!(parsevec.as_ptr(), parsevec.len(),"Asn1Imp decode buffer");
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
pub struct Asn1Exp<T : Asn1Op,const TAG:u8=0> {
	pub val : T,
	tag : u8,
	data : Vec<u8>,
}


impl<T: Asn1Op, const TAG:u8> Asn1Op for Asn1Exp<T,TAG> {
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.encode_json(key,val);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.decode_json(key,val);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		let  mut parsevec : Vec<u8>;
		let encv :Vec<u8>;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_FILTER_MASK) != ASN1_IMP_SET_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_FILTER_MASK[0x{:02x}] != ASN1_IMP_SET_MASK [0x{:02x}]", flag, ASN1_IMP_FILTER_MASK,ASN1_IMP_SET_MASK}
		}

		let ctag = code[0] & ASN1_PRIMITIVE_TAG;
		if ctag != self.tag {
			asn1obj_new_error!{Asn1ComplexError,"tag [0x{:02x}] != self.tag [0x{:02x}]", ctag, self.tag}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
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

		retv[0] = self.tag | ASN1_IMP_SET_MASK;
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let s = asn1_format_line(tab,&format!("{} IMP", name));
		let _ = iowriter.write(s.as_bytes())?;
		let _ = self.val.print_asn1(name,tab,iowriter)?;
		Ok(())
	}

	fn init_asn1() -> Self {
		Self {
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
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		if self.val.is_none() {
			return Ok(0);
		}
		let v :T;
		v = self.val.as_ref().unwrap().clone();
		let _ = v.encode_json(key,val)?;
		return Ok(1);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		if key.len() > 0 {
			let k = val.get(key);
			if k.is_none() {
				self.val = None;
				return Ok(0);
			}			
		}
		let mut v :T = T::init_asn1();
		self.val = None;
		let _ = v.decode_json(key,val)?;
		self.val = Some(v.clone());
		return Ok(1);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if ((flag as u8) & ASN1_IMP_SET_MASK) != ASN1_IMP_SET_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] & ASN1_IMP_SET_MASK[0x{:02x}] != ASN1_IMP_SET_MASK [0x{:02x}]", flag, ASN1_IMP_SET_MASK,ASN1_IMP_SET_MASK}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
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

#[derive(Clone)]
pub struct Asn1SeqSelector<T : Asn1Op +  Asn1Selector + Clone> {
	pub val : T,
	data : Vec<u8>,
}

impl<T: Asn1Op + Asn1Selector + Clone> Asn1Op for Asn1SeqSelector<T> {
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.encode_json(key,val);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.decode_json(key,val);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if (flag as u8) != ASN1_SEQ_MASK {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}] != ASN1_SEQ_MASK [0x{:02x}]", flag, ASN1_SEQ_MASK}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
		}

		retv += hdrlen;
		asn1obj_log_trace!("totallen {}",totallen);
		while retv < (totallen + hdrlen) {
			let mut v :T = T::init_asn1();
			let c = v.decode_asn1(&(code[retv..(hdrlen+totallen)]))?;
			asn1obj_log_trace!("c [{}]",c);
			if c != totallen {
				asn1obj_new_error!{Asn1ComplexError, "c [{}] != totallen [{}]", c, totallen}
			}
			retv += c;
			self.val = v.clone();
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

		encv = self.val.encode_asn1()?;
		retv = asn1obj_format_header(ASN1_SEQ_MASK as u64,encv.len() as u64);
		for i in 0..encv.len() {
			retv.push(encv[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let s = format!("[{}]Asn1SeqSelector",name);
		let _ = self.val.print_asn1(&s,tab,iowriter)?;
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1SeqSelector {
			data : Vec::new(),
			val : T::init_asn1(),
		}
	}
}


impl<T: Asn1Op + Asn1Selector + Clone> Asn1Selector for Asn1SeqSelector<T> {
	fn decode_select(&self) -> Result<String,Box<dyn Error>> {
		return self.val.decode_select();
	}
	fn encode_select(&self) -> Result<String,Box<dyn Error>> {
		return self.val.encode_select();
	}
}

#[derive(Clone)]
pub struct Asn1BitSeq<T : Asn1Op> {
	pub val : T,
	data : Vec<u8>,
}


impl<T: Asn1Op> Asn1Op for Asn1BitSeq<T> {
	fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.encode_json(key,val);
	}

	fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
		return self.val.decode_json(key,val);
	}

	fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;
		asn1obj_log_trace!("flag [0x{:x}]", flag);
		if flag as u8 != ASN1_BIT_STRING_FLAG {
			/*we do have any type*/
			asn1obj_new_error!{Asn1ComplexError,"flag [0x{:02x}]  != ASN1_BIT_STRING_FLAG [0x{:02x}]", flag, ASN1_BIT_STRING_FLAG}
		}

		if totallen < 1 {
			asn1obj_new_error!{Asn1ComplexError,"totallen [{}] < 1", totallen}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"code len [{}] < ( {} + {})", code.len(),hdrlen,totallen}
		}


		retv += hdrlen + 1;

		let c = self.val.decode_asn1(&code[retv..(hdrlen + totallen)])?;
		retv += c;
		if retv != (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ComplexError,"decode [{}] != [{}] - 1", c, totallen}
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
		let vcode :Vec<u8>;
		let mut idx :usize;
		let mut bits :u8 = 0;

		vcode = self.val.encode_asn1()?;
		if vcode.len() > 0 {
			idx = vcode.len() - 1;
			while idx > 0 {
				if vcode[idx] != 0 {
					break;
				}
				idx -= 1;
			}

			if vcode[idx] == 0  || (vcode[idx] & 0x1) != 0{
				bits = 0;
			} else if (vcode[idx] & 0x2)  != 0 {
				bits = 1;
			} else if (vcode[idx] & 0x4) != 0 {
				bits = 2;
			} else if (vcode[idx] & 0x8) != 0 {
				bits = 3;
			} else if (vcode[idx] & 0x10) != 0 {
				bits = 4;
			} else if (vcode[idx] & 0x20) != 0 {
				bits = 5;
			} else if (vcode[idx] & 0x40) != 0 {
				bits = 6;
			} else if (vcode[idx] & 0x80) != 0 {
				bits = 7;
			} else {
				bits = 0;
			}			
		}

		let llen = (vcode.len() + 1) as u64;
		retv = asn1obj_format_header(ASN1_BIT_STRING_FLAG as u64, llen);
		retv.push(bits);
		for i in 0..vcode.len() {
			retv.push(vcode[i]);
		}

		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
		let cname = format!("{} Asn1BitSeq",name);
		let _ = self.val.print_asn1(&cname,tab,iowriter)?;
		Ok(())
	}

	fn init_asn1() -> Self {
		Asn1BitSeq {
			data : Vec::new(),
			val : T::init_asn1(),
		}
	}
}
