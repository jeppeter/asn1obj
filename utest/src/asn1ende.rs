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

extargs_error_class!{EcAsn1Error}




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
		let _ = bitdata.encode_json("",&mut cv)?;
		let s = serde_json::to_string_pretty(&cv)?;
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
		let cv :serde_json::value::Value;
		cv = serde_json::from_str(&s)?;
		let mut bitdata :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
		bitdata.decode_json("",&cv)?;
		bitdata.print_asn1("Asn1BitDataFlag",0,&mut sout)?;
	}
	Ok(())
}


#[extargs_map_function(asn1bitdataflagenc_handler,asn1bitdataflagdec_handler)]
pub fn load_asn1_parser(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"asn1bitflag" : 0,
		"asn1bitdataflagenc<asn1bitdataflagenc_handler>##hexval to make Asn1BitDataLeftFlag##" : {{
			"$" : "+"
		}},
		"asn1bitdataflagdec<asn1bitdataflagdec_handler>##jsonfile ... to make Asn1BitDataLeftFlag##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}