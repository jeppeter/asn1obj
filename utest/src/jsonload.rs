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

extargs_error_class!{JsonLoadError}


#[asn1_obj_selector(selector=val,other=default,shkeybag="1.2.840.113549.1.12.10.1.2",bag=["1.2.840.113549.1.12.10.1.3","1.2.840.113549.1.12.10.1.4","1.2.840.113549.1.12.10.1.5"],safes="1.2.840.113549.1.12.10.1.6")]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelector {
	pub val : Asn1Object,
}

#[asn1_choice(selector=valid)]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagSelectElem {
	pub valid : Asn1Pkcs12SafeBagSelector,
	pub shkeybag : Asn1ImpSet<Asn1X509Sig,0>,
	pub bag : Asn1ImpSet<Asn1Pkcs12Bags,0>,
	pub safes :Asn1ImpSet<Asn1Seq<Asn1Pkcs12SafeBag>,0>,
	pub other :Asn1Any,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBagElem {
	pub selectelem : Asn1Pkcs12SafeBagSelectElem,
	pub attrib : Asn1Opt<Asn1Set<Asn1X509Attribute>>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1Pkcs12SafeBag {
	pub elem : Asn1Seq<Asn1Pkcs12SafeBagElem>,
}

fn safebagjsondec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{JsonLoadError,"need binfile"}
	}

	for f in sarr.iter() {
		let code = read_file_bytes(f)?;
		let mut bag :Asn1Pkcs12Bags = Asn1Pkcs12Bags::init_asn1();
		bag.decode_asn1(&code)?;
		let mut jval :serde_json::Value = serde_json::from_str("{}")?;
		bag.encode_json("",&mut jval)?;
		let s = serde_json::to_string_pretty(&jval)?;
		println!("{} out\n{}", f,s);
	}

	Ok(())
}



fn safebagjsonenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{JsonLoadError,"need jsonfile"}
	}

	let jsons = read_file(&sarr[0])?;
	let jval :serde_json::Value = serde_json::from_str(&jsoncontent)?;
	let mut bag :Asn1Pkcs12Bags = Asn1Pkcs12Bags::init_asn1();
	let _ = bag.decode_json("",&jval)?;
	let cstr = format!("[{}] format Asn1Pkcs12Bags\n",sarr[0]);
	let mut outf = std::io::stdout();
	let _ = bag.print_asn1(&cstr,0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = bag.encode_asn1()?;
		write_file_bytes(&code,&output)?;
	}
	Ok(())
}

#[extargs_map_function(safebagjsondec_handler,safebagjsonenc_handler)]
pub fn load_json_parser(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"safebagjsonenc<safebagjsonenc_handler>##jsonfile to load ##" : {{
			"$" : 1
		}},
		"safebagjsondec<safebagjsondec_handler>##binfile ... to decode json##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}