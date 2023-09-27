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




fn asn1bitdataleftflagenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String>;
	let mut sout = std::io::stdout();
	let mut bitdata :Asn1BitDataLeftFlag = Asn1BitDataLeftFlag::init_asn1();
	init_log(ns.clone())?;
	sarr = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{EcAsn1Error,"no file specified"}
	}

	for f in sarr.iter() {
		let bn = parse_to_bigint(f)?;
		let (_,vecs) = bn.to_bytes_be();
		bitdata.data = vecs.clone();
		let odata = bitdata.encode_asn1()?;
		debug_buffer_trace!(odata.as_ptr(),odata.len(),"outdata");
		bitdata.print_asn1("Asn1BitDataLeftFlag",0,&mut sout)?;
	}
	Ok(())
}



#[extargs_map_function(asn1bitdataleftflagenc_handler)]
pub fn load_asn1_parser(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"asn1bitdataleftflagenc<asn1bitdataleftflagenc_handler>##hexval to make Asn1BitDataLeftFlag##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}