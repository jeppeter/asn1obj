#[allow(unused_imports)]
use extargsparse_codegen::{extargs_load_commandline,ArgSet,extargs_map_function};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
#[allow(unused_imports)]
use extargsparse_worker::namespace::{NameSpaceEx};
#[allow(unused_imports)]
use extargsparse_worker::argset::{ArgSetImpl};
use extargsparse_worker::parser::{ExtArgsParser};
use extargsparse_worker::funccall::{ExtArgsParseFunc};

use std::cell::RefCell;
use std::sync::Arc;
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use regex::Regex;
#[allow(unused_imports)]
use std::any::Any;

use lazy_static::lazy_static;
use std::collections::HashMap;

#[allow(unused_imports)]
use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use super::strop::*;
#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use std::io::Write;


#[allow(unused_imports)]
use asn1obj_codegen::*;
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::asn1impl::*;
#[allow(unused_imports)]
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::strop::*;
#[allow(unused_imports)]
use asn1obj::*;

extargs_error_class!{EcAsn1Error}

#[asn1_sequence()]
pub struct BaseAsn1 {
	pub val :Asn1BigNum,
	pub types :Asn1Object,
}




fn asn1bitdataflagenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String>;
	let mut sout = std::io::stdout();
	let mut bitdata :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
	let flag :i64 = ns.get_int("asn1bitflag");
	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{EcAsn1Error,"no file specified"}
	}

	for f in sarr.iter() {
		let bn = parse_to_bigint(f)?;
		let (_,vecs) = bn.to_bytes_be();
		bitdata.data = vecs.clone();
		bitdata.flag = flag as u64;
		let odata = bitdata.encode_asn1()?;
		let mut cv :serde_json::value::Value = serde_json::json!({});
		let s = serde_json::to_string_pretty(&bitdata)?;
		debug_buffer_trace!(odata.as_ptr(),odata.len(),"outdata");
		bitdata.print_asn1("Asn1BitDataLeftFlag",0,&mut sout)?;
		println!("data\n{}", s);
	}
	Ok(())
}

fn asn1bitdataflagdec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String>;
	let mut sout = std::io::stdout();
	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{EcAsn1Error,"no file specified"}
	}

	for f in sarr.iter() {
		let s :String = read_file(f)?;
		let  bitdata :Asn1BitDataFlag;

		bitdata = serde_json::from_str(&s)?;		
		bitdata.print_asn1("Asn1BitDataFlag",0,&mut sout)?;
	}
	Ok(())
}

fn asn1bitdatacheck_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String>;
	let mut sout = std::io::stdout();
	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{EcAsn1Error,"no file specified"}
	}

	for f in sarr.iter() {
		let s :String = read_file(f)?;
		let bitdata :Asn1BitDataFlag ;
		bitdata = serde_json::from_str(&s)?;
		bitdata.print_asn1("Asn1BitDataFlag",0,&mut sout)?;
		let mut bitd :Asn1BitData = Asn1BitData::init_asn1();
		let vdata = bitdata.encode_asn1()?;
		let ores = bitd.decode_asn1(&vdata);
		if ores.is_err() {
			println!("decode Asn1BitData error {}", ores.err().unwrap());
		} else {
			bitd.print_asn1("Asn1BitData",0,&mut sout)?;
		}

		let mut bits :Asn1BitString = Asn1BitString::init_asn1();
		let ores = bits.decode_asn1(&vdata);
		if ores.is_err() {
			println!("decode Asn1BitString error {}", ores.err().unwrap());
		} else {
			bits.print_asn1("Asn1BitString",0,&mut sout)?;
		}
	}
	Ok(())
}


fn asn1fmt_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let mut vx :Vec<u8> = vec![10,20,30];
	init_log(ns.clone())?;

	while vx.len() < 35 {
		vx.push(0);
	}

	asn1_enter_debug();
	asn1_format_debug!("debug value {}",1);
	asn1_format_debug_buffer!(vx.as_ptr(),vx.len(),"vx buffer");
	asn1_enter_debug();
	asn1_format_debug!("debug value {}",1);
	asn1_format_debug_buffer!(vx.as_ptr(),vx.len(),"vx buffer");

	asn1_leave_debug();
	asn1_leave_debug();
	Ok(())
}

#[extargs_map_function(asn1bitdataflagenc_handler,asn1bitdataflagdec_handler,asn1bitdatacheck_handler,asn1fmt_handler)]
pub fn load_asn1_parser(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"asn1bitflag" : 0,
		"asn1fmt<asn1fmt_handler>##to give asn1fmt output##" : {{
			"$" : 0
		}},
		"asn1bitdataflagenc<asn1bitdataflagenc_handler>##hexval to make Asn1BitDataLeftFlag##" : {{
			"$" : "+"
		}},
		"asn1bitdataflagdec<asn1bitdataflagdec_handler>##jsonfile ... to make Asn1BitDataLeftFlag##" : {{
			"$" : "+"
		}},
		"asn1bitdatacheck<asn1bitdatacheck_handler>##jsonfile ... to load in Asn1BitDataFlag then check Asn1BitData and Asn1BitString##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}