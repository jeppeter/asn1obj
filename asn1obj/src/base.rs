

use std::error::Error;
use crate::asn1impl::{Asn1Op};
use crate::consts::{ASN1_PRIMITIVE_TAG,ASN1_CONSTRUCTED,ASN1_INTEGER_FLAG};

asn1obj_error_class!{Asn1ObjBaseError}

pub struct Ans1Integer {
	pub val :i64,
	data :Vec<u8>,
}

pub fn asn1obj_extract_len_flag(code :&[u8]) -> Result<(u64,usize),Box<dyn Error>> {
	let mut flag :u64 = 0;
	let mut totallen :usize = 0;
	let mut i :u64;
	let mut llen :usize = 0;
	if code.len() < 2 {
		asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
	}

	i = code[llen]  & ASN1_PRIMITIVE_TAG;
	if i == ASN1_PRIMITIVE_TAG {
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
		flag = i;
	} else {
		flag = i;
		llen += 1;
	}

}

impl Asn1Op for Ans1Integer {
	fn init_asn1() -> Self {
		Ans1Integer {
			val : 0,
			data : Vec::new(),
		}
	}

	fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
		let mut retv :usize = 0;
		if code.len() < 2 {
			asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
		}
		if code[0] != ASN1_INTEGER_FLAG {
			asn1obj_new_error!{Asn1ObjBaseError,"[0][0x{:02x}] != [0x{:02x}]", code[0],ASN1_INTEGER_FLAG}
		}

		/**/
	}
}
