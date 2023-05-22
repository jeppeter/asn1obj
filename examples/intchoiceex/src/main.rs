use asn1obj_codegen::{asn1_sequence,asn1_int_choice};
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::asn1impl::{Asn1Op};
use asn1obj::strop::asn1_format_line;

use std::error::Error;
use std::io::Write;
use serde_json;


#[derive(Clone)]
#[asn1_int_choice(unicode=0,ascii=1,selector=stype)]
pub struct SpcString {
	pub stype :i32,
	pub unicode : Asn1Imp<Asn1OctData,0>,
	pub ascii :Asn1Imp<Asn1OctData,1>,
}


#[derive(Clone)]
#[asn1_sequence()]
pub struct SpcSerializedObject {
	pub classid :Asn1OctData,
	pub serializeddata : Asn1OctData,
}

#[derive(Clone)]
#[asn1_int_choice(selector=stype,url=0,moniker=1,file=2)]
pub struct SpcLink {
	pub stype :i32,
	pub url :Asn1Imp<Asn1OctData,0>,
	pub moniker :Asn1Imp<SpcSerializedObject,1>,
	pub file :Asn1Imp<SpcString,2>,
}

fn format_vecs(buf :&[u8], tab :i32) -> String {
	let mut outs :String = "".to_string();
	let mut lasti : usize = 0;
	let mut ki :usize;
	for i in 0..buf.len() {
		if (i%16) == 0 {
			if i > 0 {
				outs.push_str("    ");
				while lasti != i {
					if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
						outs.push(buf[lasti] as char);
					} else {
						outs.push_str(".");
					}
					lasti += 1;
				}
				outs.push_str("\n");
			}

			for _j in 0..tab {
				outs.push_str("    ");
			}
		}
		if (i % 16) == 0 {
			outs.push_str(&format!("{:02x}", buf[i]));	
		} else {
			outs.push_str(&format!(":{:02x}", buf[i]));	
		}
		
	}

	if lasti != buf.len() {
		ki = buf.len();
		while (ki % 16) != 0 {
			outs.push_str("   ");
			ki += 1;
		}
		outs.push_str("    ");
		while lasti != buf.len() {
			if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
				outs.push(buf[lasti] as char);
			} else {
				outs.push_str(".");
			}
			lasti += 1;
		}
	}
	outs.push_str("\n");
	return outs;
}

fn main() -> Result<(),Box<dyn Error>> {
	let mut sps :SpcString = SpcString::init_asn1();
	sps.stype = 0;
	sps.unicode.val.data = vec![0x1,0x2,0x3];
	let mut spl :SpcLink = SpcLink::init_asn1();
	spl.stype = 2;
	spl.file.val = sps.clone();
	let outd = spl.encode_asn1()?;
	let mut outf = std::io::stdout();
	let outs = format!("outdata\n{}",format_vecs(&outd,1));
	outf.write(outs.as_bytes())?;
	spl.print_asn1("SpcLink",0,&mut outf)?;
	let mut outspl :SpcLink = SpcLink::init_asn1();
	let _ = outspl.decode_asn1(&outd)?;
	outspl.print_asn1("Out SpcLink",0,&mut outf)?;


	let mut sps :SpcString = SpcString::init_asn1();
	sps.stype = 1;
	sps.ascii.val.data = vec![0x1,0x2,0x3];
	let mut spl :SpcLink = SpcLink::init_asn1();
	spl.stype = 2;
	spl.file.val = sps.clone();
	let outd = spl.encode_asn1()?;
	let outs = format!("outdata\n{}",format_vecs(&outd,1));
	outf.write(outs.as_bytes())?;
	spl.print_asn1("SpcLink",0,&mut outf)?;
	let mut outspl :SpcLink = SpcLink::init_asn1();
	let _ = outspl.decode_asn1(&outd)?;
	outspl.print_asn1("Out SpcLink",0,&mut outf)?;


	Ok(())
}
