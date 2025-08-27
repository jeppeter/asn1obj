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

use serde::{Serialize,Deserialize};

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
use super::*;

use std::io::Write;


use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::asn1impl::Asn1Op;
use asn1obj::strop::asn1_format_line;
use asn1obj::{asn1obj_new_error,asn1obj_error_class};
use asn1obj_codegen::asn1_sequence;


extargs_error_class!{Asn1TestError}


#[asn1_sequence()]
struct ComplexAsn1 {
	#[serde(default="obj_default")]
	pub objval :Asn1Seq<Asn1Object>,
	#[serde(default="bignum_default")]
	pub intval :Asn1Set<Asn1BigNum>,
	#[asn1_gen(initfn = "cint_default")]
	#[serde(default = "cint_default")]
	pub cintval :i32,
}

fn cint_default() -> i32 {
	0
}

fn obj_default() -> Asn1Seq<Asn1Object> {
	Asn1Seq::init_asn1()
}

fn bignum_default() -> Asn1Set<Asn1BigNum> {
	Asn1Set::init_asn1()
}



fn asn1load_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");

	init_log(ns.clone())?;

	if sarr.len() < 1 {
		extargs_new_error!{Asn1TestError,"need binfile"}
	}

	for f in sarr.iter() {
		let s = read_file(f)?;
		let pat :ComplexAsn1 = serde_json::from_str(&s)?;
		let mut f = std::io::stdout();
		pat.print_asn1("ComplexAsn1",0,&mut f)?;

		let outs = serde_json::to_string_pretty(&pat)?;
		println!("outs\n{}",outs);
	}

	Ok(())
}




#[extargs_map_function(asn1load_handler)]
pub fn load_asn1_command(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"asn1load<asn1load_handler>##jsonfile ... to load ##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}