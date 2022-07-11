

use std::error::Error;
use crate::asn1impl::{Asn1Op};
use crate::consts::{ASN1_PRIMITIVE_TAG,ASN1_CONSTRUCTED,ASN1_INTEGER_FLAG,ASN1_MAX_INT,ASN1_MAX_LONG,ASN1_MAX_INT_1,ASN1_MAX_INT_2,ASN1_MAX_INT_3,ASN1_MAX_INT_4,ASN1_MAX_INT_NEG_1,ASN1_MAX_INT_NEG_2,ASN1_MAX_INT_NEG_3,ASN1_MAX_INT_NEG_4,ASN1_MAX_INT_NEG_5};
use crate::strop::{asn1_format_line};
use crate::{asn1obj_error_class,asn1obj_new_error};

use std::io::{Write};

use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};


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


