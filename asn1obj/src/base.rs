

use std::error::Error;
use crate::asn1impl::{Asn1Op};
use crate::consts::{ASN1_PRIMITIVE_TAG,ASN1_CONSTRUCTED,ASN1_INTEGER_FLAG,ASN1_MAX_INT,ASN1_MAX_LONG};
use crate::strop::{asn1_format_line};
use crate::{asn1obj_error_class,asn1obj_new_error};

use std::io::{Write};

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
	if i == ASN1_PRIMITIVE_TAG as u64 {
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
			if i > (ASN1_MAX_INT  >> 7){
				asn1obj_new_error!{Asn1ObjBaseError,"[0x{:08x}] expose [0x{:08x}]", i, ASN1_MAX_INT}
			}
		}
		i <<= 7;
		i += (code[llen] & 0x7f) as u64;
		llen += 1;
		flag = i;
	} else {
		flag = i;
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
				llen += 1;
				i -= 1;
			}
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

	Ok((flag,llen,totallen))
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
		if (code[0] & 0x80) != 0 {
			neg = true;
		}

		if totallen == 1 {
			if neg {
				ival = ((code[0] ^ 0xff) + 1) as i64;
				ival = - ival;
			} else {
				ival = code[0] as i64;
			}
		} else {
			if neg {
				let mut cval :u64;
				let mut uval :u64;
				cval = 0;
				for _ in 0..totallen {
					cval <<= 8;
					cval += 0xff as u64;
				}

				uval = 0;
				for i in 0..totallen {
					uval <<= 8;
					uval += (code[hdrlen+i]) as u64;
				}

				if totallen == 8 {
					let mut cc :u64 = cval + uval;
					cc += 1;
					ival = cc as i64;
					ival = - ival;
				} else {
					ival = (cval + uval) as i64;
					ival -= cval as i64 ;
					ival -= 1;
					ival = - ival;
				}
			} else {				
				ival = 0;
				for i in 0..totallen {
					ival <<= 8;
					ival += (code[hdrlen+i]) as i64;
				}
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
		for i in 0..8 {
			let c = ((self.val >> ((7-i) * 8)) & 0xff) as u8;
			retv.push(c);
		}
		Ok(retv)
	}

	fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {		
		let s = asn1_format_line(tab,&(format!("{}: ASN1_INTEGER {}", name, self.val)));
		iowriter.write(s.as_bytes())?;
		Ok(())
	}
}


