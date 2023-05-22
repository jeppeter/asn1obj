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
	pub url :Asn1ImpSet<Asn1OctData,0>,
	pub moniker :Asn1ImpSet<SpcSerializedObject,1>,
	pub file :Asn1ImpSet<SpcString,2>,
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
	spl.file.val.push(sps.clone());
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
	spl.file.val.push(sps.clone());
	let outd = spl.encode_asn1()?;
	let mut outf = std::io::stdout();
	let outs = format!("outdata\n{}",format_vecs(&outd,1));
	outf.write(outs.as_bytes())?;
	spl.print_asn1("SpcLink",0,&mut outf)?;
	let mut outspl :SpcLink = SpcLink::init_asn1();
	let _ = outspl.decode_asn1(&outd)?;
	outspl.print_asn1("Out SpcLink",0,&mut outf)?;



	let mut sps :SpcSerializedObject = SpcSerializedObject::init_asn1();
	sps.classid.data = vec![0x1,0x2,0x3];
	sps.serializeddata.data = vec![0x4,0x5,0x6];
	let mut spl :SpcLink = SpcLink::init_asn1();
	spl.stype = 1;
	spl.moniker.val.push(sps.clone());
	let outd = spl.encode_asn1()?;
	let outs = format!("outdata\n{}",format_vecs(&outd,1));
	outf.write(outs.as_bytes())?;
	spl.print_asn1("SpcLink",0,&mut outf)?;
	let mut outspl :SpcLink = SpcLink::init_asn1();
	let _ = outspl.decode_asn1(&outd)?;
	outspl.print_asn1("Out SpcLink",0,&mut outf)?;


	let mut sps :Asn1OctData = Asn1OctData::init_asn1();
	sps.data = vec![0x33,0x44,0x55];
	let mut spl :SpcLink = SpcLink::init_asn1();
	spl.stype = 0;
	spl.url.val.push(sps.clone());
	let outd = spl.encode_asn1()?;
	let outs = format!("outdata\n{}",format_vecs(&outd,1));
	outf.write(outs.as_bytes())?;
	spl.print_asn1("SpcLink",0,&mut outf)?;
	let mut outspl :SpcLink = SpcLink::init_asn1();
	let _ = outspl.decode_asn1(&outd)?;
	outspl.print_asn1("Out SpcLink",0,&mut outf)?;


	Ok(())
}

/*
output:
outdata
    a2:05:80:03:01:02:03                               .......
SpcLink.stype type 2
    file[0].stype type 0
        unicode IMP
        unicode: ASN1_OCT_DATA
            01:02:03                                           ...
Out SpcLink.stype type 2
    file[0].stype type 0
        unicode IMP
        unicode: ASN1_OCT_DATA
            01:02:03                                           ...
outdata
    a2:05:81:03:01:02:03                               .......
SpcLink.stype type 2
    file[0].stype type 1
        ascii IMP
        ascii: ASN1_OCT_DATA
            01:02:03                                           ...
Out SpcLink.stype type 2
    file[0].stype type 1
        ascii IMP
        ascii: ASN1_OCT_DATA
            01:02:03                                           ...
outdata
    a1:0a:04:03:01:02:03:04:03:04:05:06                ............
SpcLink.stype type 1
    moniker[0] SpcSerializedObject
        classid: ASN1_OCT_DATA
            01:02:03                                           ...
        serializeddata: ASN1_OCT_DATA
            04:05:06                                           ...
Out SpcLink.stype type 1
    moniker[0] SpcSerializedObject
        classid: ASN1_OCT_DATA
            01:02:03                                           ...
        serializeddata: ASN1_OCT_DATA
            04:05:06                                           ...
outdata
    a0:05:04:03:33:44:55                               ....3DU
SpcLink.stype type 0
    url[0]: ASN1_OCT_DATA
        33:44:55                                           3DU
Out SpcLink.stype type 0
    url[0]: ASN1_OCT_DATA
        33:44:55                                           3DU
*/
