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
use asn1obj::asn1impl::{Asn1Op,Asn1Selector};
use asn1obj::strop::{asn1_format_line};
use asn1obj::{asn1obj_new_error,asn1obj_error_class};
use asn1obj_codegen::{asn1_sequence,asn1_obj_selector,asn1_int_choice,asn1_choice};


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


#[derive(Clone,Serialize,Deserialize)]
#[asn1_obj_selector(noclone,noserialize,nodeserialize,selector=stype,ccv="1.2.3",bbv="1.2.4",ddv="1.2.5",ddv=default)]
struct BBSelectorauto {
	pub stype :Asn1Object,
}

#[derive(Clone,Serialize,Deserialize)]
#[asn1_choice(noclone,noserialize,nodeserialize,selector=seltype)]
struct BBTestauto {
	pub seltype :BBSelectorauto,
	pub ccv :Asn1Object,
	pub bbv :Asn1BigNum,
	pub ddv :Asn1PrintableString,
}

#[derive(Clone,Serialize,Deserialize)]
#[asn1_sequence(noclone,noserialize,nodeserialize)]
struct BBTestautoSeq {
	pub elem :Asn1Seq<BBTestauto>,
}


fn asn1objload_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");

	init_log(ns.clone())?;

	if sarr.len() < 1 {
		extargs_new_error!{Asn1TestError,"need binfile"}
	}

	for f in sarr.iter() {
		let s = read_file(f)?;
		let pat :BBTestautoSeq = serde_json::from_str(&s)?;
		let mut f = std::io::stdout();
		pat.print_asn1("BBTestautoSeq",0,&mut f)?;

		let outs = serde_json::to_string_pretty(&pat)?;
		println!("outs\n{}",outs);
	}

	Ok(())
}

#[derive(Clone,Serialize,Deserialize)]
#[asn1_int_choice(noclone,noserialize,nodeserialize,ccv=1,bbv=2,ddv=3,selector=seltype)]
struct IntTestauto {
	pub seltype :i32,
	pub ccv :Asn1Object,
	pub bbv :Asn1BigNum,
	pub ddv :Asn1PrintableString,
}


#[derive(Clone,Serialize,Deserialize)]
#[asn1_sequence(noclone,noserialize,nodeserialize)]
struct IntTestautoSeq {
	pub elem :Asn1Seq<IntTestauto>,
}

fn asn1intload_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");

	init_log(ns.clone())?;

	if sarr.len() < 1 {
		extargs_new_error!{Asn1TestError,"need binfile"}
	}

	for f in sarr.iter() {
		let s = read_file(f)?;
		let pat :IntTestautoSeq = serde_json::from_str(&s)?;
		let mut f = std::io::stdout();
		pat.print_asn1("IntTestautoSeq",0,&mut f)?;

		let outs = serde_json::to_string_pretty(&pat)?;
		println!("outs\n{}",outs);
	}

	Ok(())
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509AlgorElem {
	pub algorithm : Asn1Object,
	pub parameters : Asn1Opt<Asn1Any>,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1X509Algor {
	pub elem : Asn1Seq<Asn1X509AlgorElem>,
}


#[asn1_sequence()]
#[derive(Clone)]
pub struct RsaPssSigInfoElem {
	pub algo :Asn1ImpSet<Asn1X509Algor,0>,
	pub cmplx :Asn1ImpSet<Asn1X509Algor,1>,
	pub size :Asn1ImpSet<Asn1Integer,2>,
}


fn pssinfodec_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {

	let sarr :Vec<String>;
	let mut stdout = std::io::stdout();

	init_log(ns.clone())?;

	sarr = ns.get_array("subnargs");
	for f in sarr.iter() {
		let code = read_file_bytes(f)?;
		debug_buffer_trace!(code.as_ptr(),code.len(),"[{}]code in",f);
		let mut rsapriv :RsaPssSigInfoElem = RsaPssSigInfoElem::init_asn1();
		let _ = rsapriv.decode_asn1(&code)?;
		rsapriv.print_asn1("RsaPssSigInfoElem",0,&mut stdout)?;
	}
	Ok(())
}


#[extargs_map_function(asn1load_handler,asn1objload_handler,asn1intload_handler,pssinfodec_handler)]
pub fn load_asn1_command(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"asn1load<asn1load_handler>##jsonfile ... to load ##" : {{
			"$" : "+"
		}},
		"asn1objload<asn1objload_handler>##jsonfile ... to load ##" : {{
			"$" : "+"
		}},
		"asn1intload<asn1intload_handler>##jsonfile ... to load ##" : {{
			"$" : "+"
		}},
		"pssinfodec<pssinfodec_handler>##binfile ... to load RsaPssSigInfoElem##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}