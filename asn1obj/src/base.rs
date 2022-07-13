

use std::error::Error;
use crate::asn1impl::{Asn1Op};
use crate::consts::{ASN1_PRIMITIVE_TAG,ASN1_CONSTRUCTED,ASN1_INTEGER_FLAG,ASN1_BOOLEAN_FLAG,ASN1_MAX_INT,ASN1_MAX_LONG,ASN1_MAX_INT_1,ASN1_MAX_INT_2,ASN1_MAX_INT_3,ASN1_MAX_INT_4,ASN1_MAX_INT_NEG_1,ASN1_MAX_INT_NEG_2,ASN1_MAX_INT_NEG_3,ASN1_MAX_INT_NEG_4,ASN1_MAX_INT_NEG_5,ASN1_MAX_INT_5,ASN1_BIT_STRING_FLAG,ASN1_OCT_STRING_FLAG,ASN1_NULL_FLAG,ASN1_OBJECT_FLAG,ASN1_ENUMERATED_FLAG,ASN1_UTF8STRING_FLAG};
use crate::strop::{asn1_format_line};
use crate::{asn1obj_error_class,asn1obj_new_error};

use std::io::{Write};

use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};

use bytes::{BytesMut,BufMut};
use regex::Regex;

use std::str::FromStr;
use std::ops::Shr;
use num_bigint::{BigUint};
use num_traits::{Zero};


asn1obj_error_class!{Asn1ObjBaseError}


pub fn asn1obj_extract_header(code :&[u8]) -> Result<(u64,usize,usize),Box<dyn Error>> {
	let flag :u64;
	let mut totallen :usize = 0;
	let mut i :u64;
	let mut llen :usize = 0;
	let inf :i32;
	let ret :u8;
	if code.len() < 2 {
		asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
	}

	i = (code[llen]  & ASN1_PRIMITIVE_TAG) as u64;
	ret = code[llen] & ASN1_CONSTRUCTED;
	if i == ASN1_PRIMITIVE_TAG  as u64 {
		llen += 1;
		if code.len() <= llen {
			asn1obj_new_error!{Asn1ObjBaseError,"expose [{}] len", code.len()}
		}
		i = 0;
		while (code[llen] & 0x80) != 0x0 {
			i <<= 7;
			i += (code[llen] & 0x7f) as u64;
			llen += 1;
			if code.len() <= llen {
				asn1obj_new_error!{Asn1ObjBaseError,"expose [{}] len", code.len()}		
			}
			if i > (ASN1_MAX_INT  >> 7) {
				asn1obj_new_error!{Asn1ObjBaseError,"[0x{:08x}] expose [0x{:08x}]", i, ASN1_MAX_INT}
			}
		}
		i <<= 7;
		i += (code[llen] & 0x7f) as u64;
		llen += 1;
		flag = i;
	} else {
		flag = code[0] as u64;
		llen += 1;
	}

	if code.len() <= llen {
		asn1obj_new_error!{Asn1ObjBaseError,"expose [{}] len", code.len()}
	}

	if code[llen] == 0x80 {
		inf = 1;
		llen += 1;
	} else {
		inf = 0;
		i = (code[llen] & 0x7f) as u64;
		if (code[llen] & 0x80) != 0 {

			if code.len() <= (llen + (i as usize)) {
				asn1obj_new_error!{Asn1ObjBaseError,"llen [0x{:08x}] + [0x{:08x}] >= [0x{:08x}]", llen, i, code.len()}
			}
			/*skip this one*/
			i -= 1;
			llen += 1;
			while i > 0 && code[llen] == 0x0 {
				llen += 1;
				i -= 1;
			}

			if i > 4 {
				asn1obj_new_error!{Asn1ObjBaseError,"left [{}] > 4", i}
			}
			totallen = 0;
			while i > 0 {
				totallen <<= 8;
				totallen += (code[llen]) as usize;
				asn1obj_log_trace!("code[{}]=[0x{:02x}]",llen,code[llen]);
				llen += 1;
				i -= 1;
			}
			/*to add last one*/
			totallen <<= 8;
			totallen += (code[llen]) as usize;
			llen += 1;

			if totallen > ASN1_MAX_LONG as usize {
				asn1obj_new_error!{Asn1ObjBaseError,"totallen [0x{:x}] > [0x{:x}]", totallen, ASN1_MAX_LONG}
			}
		} else {
			totallen = i as usize;
			llen += 1;
		}
	}

	if inf != 0 && (ret & ASN1_CONSTRUCTED) == 0 {
		asn1obj_new_error!{Asn1ObjBaseError,"inf [{}] ASN1_CONSTRUCTED not", inf}
	}
	asn1obj_log_trace!("flag [0x{:02x}] llen [0x{:x}] totallen [0x{:x}]", flag, llen,totallen);
	Ok((flag,llen,totallen))
}

pub fn asn1obj_format_header(tag :u64, length :u64) -> Vec<u8> {
	let mut retv :Vec<u8> = Vec::new();
	if (tag & 0xff) == tag {
		retv.push((tag & 0xff) as u8);
	} else {
		retv.push(0x0);
	}
	if length < ASN1_MAX_INT_NEG_1 {
		retv.push((length & 0xff) as u8);
	} else if length <= ASN1_MAX_INT_1 {
		retv.push(0x81);
		retv.push((length & 0xff) as u8);		
	} else if length <= ASN1_MAX_INT_2 {
		retv.push(0x82);
		retv.push(((length >> 8) & 0xff) as u8);
		retv.push((length & 0xff) as u8);
	} else if length <= ASN1_MAX_INT_3 {
		retv.push(0x83);
		retv.push(((length >> 16) & 0xff) as u8);
		retv.push(((length >> 8) & 0xff) as u8);
		retv.push(((length >> 0) & 0xff) as u8);
	} else if length <= ASN1_MAX_INT_4 {
		retv.push(0x84);
		retv.push(((length >> 24) & 0xff) as u8);
		retv.push(((length >> 16) & 0xff) as u8);
		retv.push(((length >> 8) & 0xff) as u8);
		retv.push(((length >> 0) & 0xff) as u8);
	} else {
		panic!("can not exceed {} ",length);
	}
	return retv;
}

#[derive(Clone)]
pub struct Asn1Integer {
	pub val :i64,
	data :Vec<u8>,
}


impl Asn1Op for Asn1Integer {
	fn init_asn1() -> Self {
		Asn1Integer {
			val : 0,
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		let mut ival :i64;
		let mut neg :bool = false;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_INTEGER_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_INTEGER_FLAG [0x{:02x}]", flag,ASN1_INTEGER_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}

		if totallen < 1 {
			asn1obj_new_error!{Asn1ObjBaseError,"need 1 length"}
		}
		if (code[hdrlen] & 0x80) != 0 {
			neg = true;
		}



		if neg {
			let mut uval :u64;
			uval = 0;
			for i in 0..totallen {
				uval <<= 8;
				uval += (code[hdrlen+i]) as u64;
				asn1obj_log_trace!("[0x{:x}]", uval);
			}

			if uval <= ASN1_MAX_INT_1 {
				ival = (ASN1_MAX_INT_1 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_2 {
				ival = (ASN1_MAX_INT_2 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_3 {
				ival = (ASN1_MAX_INT_3 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_4 {
				ival = (ASN1_MAX_INT_4 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_5 {
				ival = (ASN1_MAX_INT_5 - uval + 1) as i64;
			} else {
				asn1obj_new_error!{Asn1ObjBaseError,"invalid uval [0x{:x}]", uval}
			}

			asn1obj_log_trace!("ival {}",ival);
			ival = -ival;
		} else {				
			ival = 0;
			for i in 0..totallen {
				ival <<= 8;
				ival += (code[hdrlen+i]) as i64;
			}
		}
		self.val = ival;
		self.data = Vec::new();
		for i in 0..(hdrlen + totallen) {
			self.data.push(code[i]);
		}
		retv= hdrlen + totallen;
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		retv.push(ASN1_INTEGER_FLAG);
		retv.push(8);
		if self.val >= 0 {
			if self.val < ASN1_MAX_INT_NEG_1 as i64 {
				retv.push((self.val & 0xff) as u8);
				retv[1] = 1;
			} else if self.val < ASN1_MAX_INT_NEG_2 as i64 {
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 2;
			} else if self.val < ASN1_MAX_INT_NEG_3 as i64 {
				retv.push(((self.val >> 16) & 0xff) as u8);
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 3;
			} else if self.val < ASN1_MAX_INT_NEG_4 as i64 {
				retv.push(((self.val >> 24) & 0xff) as u8);
				retv.push(((self.val >> 16) & 0xff) as u8);
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 4;
			} else if self.val < ASN1_MAX_INT_NEG_5 as i64 {
				retv.push(((self.val >> 32) & 0xff) as u8);
				retv.push(((self.val >> 24) & 0xff) as u8);
				retv.push(((self.val >> 16) & 0xff) as u8);
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 5;
			} else {
				asn1obj_new_error!{Asn1ObjBaseError,"value [0x{:x}] > [0x{:x}]", self.val, ASN1_MAX_INT_NEG_4}
			}
		} else {
			let ival :i64 = - self.val;
			let mut uval :u64 = self.val as u64;
			uval = uval ^ 0;
			asn1obj_log_trace!("ival [{}] uval [{}]",ival,uval);
			if ival <= ASN1_MAX_INT_NEG_1 as i64 {
				retv.push((uval & 0xff) as u8);
				retv[1] = 1;
			} else if ival <= ASN1_MAX_INT_NEG_2 as i64 {
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 2;
			} else if ival <= ASN1_MAX_INT_NEG_3 as i64 {
				retv.push(((uval >> 16) & 0xff) as u8);
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 3;
			} else if ival <= ASN1_MAX_INT_NEG_4 as i64 {
				retv.push(((uval >> 24) & 0xff) as u8);
				retv.push(((uval >> 16) & 0xff) as u8);
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 4;
			} else if ival <= ASN1_MAX_INT_NEG_5 as i64 {
				retv.push(((uval >> 32) & 0xff ) as u8);
				retv.push(((uval >> 24) & 0xff) as u8);
				retv.push(((uval >> 16) & 0xff) as u8);
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 5;
			} else {
				asn1obj_new_error!{Asn1ObjBaseError,"neg value [0x{:x}] >= [0x{:x}]", uval, ASN1_MAX_INT_NEG_4}
			}
			asn1obj_log_trace!("retv {:?}", retv);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_INTEGER {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct Asn1Boolean {
	pub val :bool,
	data :Vec<u8>,
}

impl Asn1Op for Asn1Boolean {
	fn init_asn1() -> Self {
		Asn1Boolean {
			val : false,
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_BOOLEAN_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_BOOLEAN_FLAG [0x{:02x}]", flag,ASN1_BOOLEAN_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}

		if totallen != 1 {
			asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] != 1", totallen}
		}

		if code[hdrlen]  != 0 {
			self.val = true;
		} else {
			self.val = false;
		}

		retv = hdrlen + totallen;
		self.data = Vec::new();
		for i in 0..retv {
			self.data.push(code[i]);
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		retv.push(ASN1_BOOLEAN_FLAG);
		retv.push(1);
		if self.val  {
			retv.push(0xff);
		} else {
			retv.push(0)
		}		
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_BOOLEAN {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct Asn1BitString {
	pub val :String,
	data :Vec<u8>,
}


impl Asn1Op for Asn1BitString {
	fn init_asn1() -> Self {
		Asn1BitString {
			val : "".to_string(),
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_BIT_STRING_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_BIT_STRING_FLAG [0x{:02x}]", flag,ASN1_BIT_STRING_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}

		if totallen < 1 {
			asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] < 1", totallen}
		}

		let mut retm = BytesMut::with_capacity(totallen - 1);
		for i in 1..totallen {
			retm.put_u8(code[hdrlen + i]);
		}
		let a = retm.freeze();
		self.val = String::from_utf8_lossy(&a).to_string();
		self.data = Vec::new();
		retv = hdrlen + totallen;
		for i in 0..retv {
			self.data.push(code[i]);
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let vcode = self.val.as_bytes();
		let llen :u64 = (vcode.len() + 1) as u64;
		let mut retv :Vec<u8>;
		let bits :u8;
		let mut idx :usize;

		retv = asn1obj_format_header(ASN1_BIT_STRING_FLAG as u64,llen);
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

		retv.push(bits);
		for i in 0..vcode.len() {
			retv.push(vcode[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_BIT_STRING {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}


#[derive(Clone)]
pub struct Asn1OctString {
	pub val :String,
	data :Vec<u8>,
}


impl Asn1Op for Asn1OctString {
	fn init_asn1() -> Self {
		Asn1OctString {
			val : "".to_string(),
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_OCT_STRING_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_OCT_STRING_FLAG [0x{:02x}]", flag,ASN1_OCT_STRING_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}


		let mut retm = BytesMut::with_capacity(totallen);
		for i in 0..totallen {
			retm.put_u8(code[hdrlen + i]);
		}
		let a = retm.freeze();
		self.val = String::from_utf8_lossy(&a).to_string();
		self.data = Vec::new();
		retv = hdrlen + totallen;
		for i in 0..retv {
			self.data.push(code[i]);
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let vcode = self.val.as_bytes();
		let llen :u64 = (vcode.len() ) as u64;
		let mut retv :Vec<u8>;

		retv = asn1obj_format_header(ASN1_OCT_STRING_FLAG as u64,llen);

		for i in 0..vcode.len() {
			retv.push(vcode[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_OCT_STRING {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct Asn1Null {
	data :Vec<u8>,
}


impl Asn1Op for Asn1Null {
	fn init_asn1() -> Self {
		Asn1Null {
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_NULL_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_NULL_FLAG [0x{:02x}]", flag,ASN1_NULL_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}

		if totallen != 0 {
			asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] != 0",totallen}
		}

		self.data = Vec::new();
		retv = hdrlen + totallen;
		for i in 0..retv {
			self.data.push(code[i]);
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let retv :Vec<u8>;
		retv = asn1obj_format_header(ASN1_NULL_FLAG as u64,0);
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_NULL", name)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}


#[derive(Clone)]
pub struct Asn1Object {
	val :String,
	data :Vec<u8>,
}

const ULONG_MAX :u64 = 0xffffffffffffffff;

impl Asn1Object {
	pub fn set_value(&mut self,val :&str) -> Result<String,Box<dyn Error>> {
		let restr = format!("^([0-9\\.]+)$");
		let oldstr :String;
		let vo = Regex::new(&restr);
		if vo.is_err() {
			let err = vo.err().unwrap();
			asn1obj_new_error!{Asn1ObjBaseError,"can parse [{}] error [{:?}]", restr,err}
		}
		let re = vo.unwrap();
		if !re.is_match(val) {
			asn1obj_new_error!{Asn1ObjBaseError,"[{}] not valid for [{}]", val, restr}
		}
		let sarr :Vec<&str> = val.split(".").collect();
		if sarr.len() < 1 {
			asn1obj_new_error!{Asn1ObjBaseError,"need at least 1 number"}
		}
		if sarr[0] != "1" && sarr[0] != "1" {
			asn1obj_new_error!{Asn1ObjBaseError,"must start 1. or 2. not [{}.]",sarr[0]}
		}

		for s in sarr.iter() {
			if s.len() == 0 {
				asn1obj_new_error!{Asn1ObjBaseError,"not allow [] empty on in the [{}]",val}
			}
		}

		oldstr = format!("{}",self.val);
		self.val = val.to_string();
		Ok(oldstr)
	}

	pub fn get_value(&self) -> String {
		return format!("{}",self.val);
	}

	fn decode_object(&self,v8 :&[u8]) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		let mut bn :BigUint = Zero::zero();
		let mut l :u64;
		let mut lenv :usize = v8.len();
		let mut usebn :bool;
		let mut idx :usize = 0;
		let mut bfirst :bool = true;
		let mut i :u32;

		while lenv > 0 {
			l = 0;
			usebn = false;
			loop {
				let c = v8[idx];
				idx += 1;
				lenv -= 1;
				if lenv == 0 && (c & 0x80) != 0 {
					asn1obj_new_error!{Asn1ObjBaseError,"c [0x{:02x}] at the end",c}
				}
				if usebn {
					bn += c & 0x7f;
					asn1obj_log_trace!("bn [{}]",bn);
				} else {
					l += (c & 0x7f) as u64;
					asn1obj_log_trace!("l [{}]", l);
				}

				if (c & 0x80) == 0 {
					break;
				}

				if !usebn && l >( ULONG_MAX >> 7) {
					bn = Zero::zero();
					bn += l;
					usebn = true;
				}

				if usebn {
					bn <<= 7;
				} else {
					l <<= 7;
				}
			}

			if bfirst {
				bfirst = false;
				if l >= 80 {
					i = 2;
					if usebn {
						bn -= 80 as u64;
					} else {
						l -= 80;
					}
				} else {
					i = (l / 40) as u32;
					l -= (i * 40) as u64;
				}

				asn1obj_log_trace!("i {}",i);
				rets.push_str(&format!("{}",i));

			} 
			if usebn {
				rets.push_str(".");
				rets.push_str(&format!("{}",bn));
			} else {
				rets.push_str(".");
				rets.push_str(&format!("{}", l));
			}
		}

		Ok(rets)
	}

	fn encode_object(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		let mut idx :usize = 0;
		let sarr :Vec<&str> = self.val.split(".").collect();
		let  mut curn :u64 = 0;
		for v in sarr.iter() {
			match u64::from_str_radix(v,10) {
				Ok(cn) => {
					if idx < 2 {
						if idx == 0 {
							curn = cn;
						} else {
							curn *= 40;
							curn += cn;

							retv.push(curn as u8);
							curn = 0;
						}

					} else {
						let mut maxidx :usize = 0;

						curn = cn;
						loop {
							if (curn >> (maxidx * 7))  == 0 {
								break;
							}
							maxidx += 1;
						}

						if maxidx == 0 {
							retv.push(0);
						} else {
							while maxidx > 1 {
								let bb :u8 = ((cn >> ((maxidx - 1) * 7)) & 0x7f) as u8;
								retv.push(bb | 0x80 );
								maxidx -= 1;
							}
							if maxidx == 1 {
								let bb :u8 = (cn & 0x7f) as u8;
								retv.push(bb);
							}
						}

					}
					idx += 1;
				},
				Err(e) => {
					match BigUint::from_str(v) {
						Ok(bn2) => {
							if idx < 2 {
								asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] at [{}] with bigint", self.val,v}
							}

							let mut maxidx :usize = 0;
							loop {
								let bn :BigUint = bn2.clone();
								let cb :BigUint = bn.shr(maxidx * 7);
								let zb :BigUint = Zero::zero();
								if cb.eq(&zb) {
									break;
								}
								maxidx += 1;
							}

							if maxidx < 1 {
								asn1obj_new_error!{Asn1ObjBaseError	,"bignum is {} to small", bn2}
							} else {
								while maxidx > 1 {
									let bn :BigUint = bn2.clone();
									let cb :BigUint = bn.shr((maxidx - 1) * 7);
									let bv :Vec<u8> = cb.to_bytes_le();
									let bb :u8 = bv[0] & 0x7f;
									retv.push(bb | 0x80);
									maxidx -= 1;
								}

								let bv :Vec<u8> = bn2.to_bytes_le();
								let bb :u8 = bv[0] & 0x7f;
								retv.push(bb);
							}

							idx += 1;
						},
						Err(_e2) => {
							asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] at [{}] {:?}", self.val,v,e}
						}
					}
				}
			}
		}
		Ok(retv)
	}
}


impl Asn1Op for Asn1Object {
	fn init_asn1() -> Self {
		Asn1Object {
			val : "".to_string(),
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_OBJECT_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_OBJECT_FLAG [0x{:02x}]", flag,ASN1_OBJECT_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}

		let s = self.decode_object(&code[hdrlen..(hdrlen+totallen)])?;
		self.val = s;
		self.data = Vec::new();
		retv = hdrlen + totallen;
		for i in 0..retv {
			self.data.push(code[i]);
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8>;
		if self.val.len() == 0 {
			asn1obj_new_error!{Asn1ObjBaseError,"not set val yet"}
		}
		let vv :Vec<u8> = self.encode_object()?;
		retv = asn1obj_format_header(ASN1_OBJECT_FLAG as u64,vv.len() as u64);
		for v in vv.iter() {
			retv.push(*v);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_OBJECT {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}


#[derive(Clone)]
pub struct Asn1Enumerated {
	pub val :i64,
	data :Vec<u8>,
}


impl Asn1Op for Asn1Enumerated {
	fn init_asn1() -> Self {
		Asn1Enumerated {
			val : 0,
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		let mut ival :i64;
		let mut neg :bool = false;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_ENUMERATED_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_ENUMERATED_FLAG [0x{:02x}]", flag,ASN1_ENUMERATED_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}

		if totallen < 1 {
			asn1obj_new_error!{Asn1ObjBaseError,"need 1 length"}
		}
		if (code[hdrlen] & 0x80) != 0 {
			neg = true;
		}



		if neg {
			let mut uval :u64;
			uval = 0;
			for i in 0..totallen {
				uval <<= 8;
				uval += (code[hdrlen+i]) as u64;
				asn1obj_log_trace!("[0x{:x}]", uval);
			}

			if uval <= ASN1_MAX_INT_1 {
				ival = (ASN1_MAX_INT_1 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_2 {
				ival = (ASN1_MAX_INT_2 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_3 {
				ival = (ASN1_MAX_INT_3 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_4 {
				ival = (ASN1_MAX_INT_4 - uval + 1) as i64;
			} else if uval <= ASN1_MAX_INT_5 {
				ival = (ASN1_MAX_INT_5 - uval + 1) as i64;
			} else {
				asn1obj_new_error!{Asn1ObjBaseError,"invalid uval [0x{:x}]", uval}
			}

			asn1obj_log_trace!("ival {}",ival);
			ival = -ival;
		} else {				
			ival = 0;
			for i in 0..totallen {
				ival <<= 8;
				ival += (code[hdrlen+i]) as i64;
			}
		}
		self.val = ival;
		self.data = Vec::new();
		for i in 0..(hdrlen + totallen) {
			self.data.push(code[i]);
		}
		retv= hdrlen + totallen;
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let mut retv :Vec<u8> = Vec::new();
		retv.push(ASN1_ENUMERATED_FLAG);
		retv.push(8);
		if self.val >= 0 {
			if self.val < ASN1_MAX_INT_NEG_1 as i64 {
				retv.push((self.val & 0xff) as u8);
				retv[1] = 1;
			} else if self.val < ASN1_MAX_INT_NEG_2 as i64 {
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 2;
			} else if self.val < ASN1_MAX_INT_NEG_3 as i64 {
				retv.push(((self.val >> 16) & 0xff) as u8);
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 3;
			} else if self.val < ASN1_MAX_INT_NEG_4 as i64 {
				retv.push(((self.val >> 24) & 0xff) as u8);
				retv.push(((self.val >> 16) & 0xff) as u8);
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 4;
			} else if self.val < ASN1_MAX_INT_NEG_5 as i64 {
				retv.push(((self.val >> 32) & 0xff) as u8);
				retv.push(((self.val >> 24) & 0xff) as u8);
				retv.push(((self.val >> 16) & 0xff) as u8);
				retv.push(((self.val >> 8) & 0xff) as u8);
				retv.push((self.val & 0xff) as u8);
				retv[1] = 5;
			} else {
				asn1obj_new_error!{Asn1ObjBaseError,"value [0x{:x}] > [0x{:x}]", self.val, ASN1_MAX_INT_NEG_4}
			}
		} else {
			let ival :i64 = - self.val;
			let mut uval :u64 = self.val as u64;
			uval = uval ^ 0;
			asn1obj_log_trace!("ival [{}] uval [{}]",ival,uval);
			if ival <= ASN1_MAX_INT_NEG_1 as i64 {
				retv.push((uval & 0xff) as u8);
				retv[1] = 1;
			} else if ival <= ASN1_MAX_INT_NEG_2 as i64 {
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 2;
			} else if ival <= ASN1_MAX_INT_NEG_3 as i64 {
				retv.push(((uval >> 16) & 0xff) as u8);
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 3;
			} else if ival <= ASN1_MAX_INT_NEG_4 as i64 {
				retv.push(((uval >> 24) & 0xff) as u8);
				retv.push(((uval >> 16) & 0xff) as u8);
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 4;
			} else if ival <= ASN1_MAX_INT_NEG_5 as i64 {
				retv.push(((uval >> 32) & 0xff ) as u8);
				retv.push(((uval >> 24) & 0xff) as u8);
				retv.push(((uval >> 16) & 0xff) as u8);
				retv.push(((uval >> 8) & 0xff) as u8);
				retv.push((uval & 0xff) as u8);
				retv[1] = 5;
			} else {
				asn1obj_new_error!{Asn1ObjBaseError,"neg value [0x{:x}] >= [0x{:x}]", uval, ASN1_MAX_INT_NEG_4}
			}
			asn1obj_log_trace!("retv {:?}", retv);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_ENUMERATED {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}


#[derive(Clone)]
pub struct Asn1String {
	pub val :String,
	data :Vec<u8>,
}


impl Asn1Op for Asn1String {
	fn init_asn1() -> Self {
		Asn1String {
			val : "".to_string(),
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let retv :usize;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

		if flag != ASN1_UTF8STRING_FLAG as u64 {
			asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_UTF8STRING_FLAG [0x{:02x}]", flag,ASN1_UTF8STRING_FLAG}
		}

		if code.len() < (hdrlen + totallen) {
			asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
		}


		let mut retm = BytesMut::with_capacity(totallen);
		for i in 0..totallen {
			retm.put_u8(code[hdrlen + i]);
		}
		let a = retm.freeze();
		self.val = String::from_utf8_lossy(&a).to_string();
		self.data = Vec::new();
		retv = hdrlen + totallen;
		for i in 0..retv {
			self.data.push(code[i]);
		}
		Ok(retv)
	}

	fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
		let vcode = self.val.as_bytes();
		let llen :u64 = (vcode.len() ) as u64;
		let mut retv :Vec<u8>;

		retv = asn1obj_format_header(ASN1_UTF8STRING_FLAG as u64,llen);

		for i in 0..vcode.len() {
			retv.push(vcode[i]);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_STRING {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}
