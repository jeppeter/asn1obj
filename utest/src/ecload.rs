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
use asn1obj::complex::*;
#[allow(unused_imports)]
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::strop::asn1_format_line;
#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};

extargs_error_class!{EcLoadError}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CURVEElem {
	pub a :Asn1OctData,
	pub b :Asn1OctData,
	pub seed :Asn1Opt<Asn1BitDataFlag>,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIALELem {
	pub k1 :Asn1Integer,
	pub k2 :Asn1Integer,
	pub k3 :Asn1Integer,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIAL {
	pub elem :Asn1Seq<X9_62_PENTANOMIALELem>,
}





#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CURVE {
	pub elem :Asn1Seq<X9_62_CURVEElem>,
}

#[derive(Clone)]
#[asn1_obj_selector(other=default,onBasis="1.2.840.10045.1.2.3.1",tpBasis="1.2.840.10045.1.2.3.2",ppBasis="1.2.840.10045.1.2.3.3")]
pub struct X962Selector  {
	pub val :Asn1Object,
}

#[derive(Clone)]
#[asn1_choice(selector=otype)]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM_CHOICE {
	pub otype : X962Selector,
	pub onBasis : Asn1Null,
	pub tpBasis : Asn1BigNum,
	pub ppBasis : X9_62_PENTANOMIAL,
	pub other :Asn1Any,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM {
	pub m :Asn1Integer,
	pub elemchoice : X9_62_CHARACTERISTIC_TWO_ELEM_CHOICE,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CHARACTERISTIC_TWO {
	pub elem :Asn1Seq<X9_62_CHARACTERISTIC_TWO_ELEM>,
}


#[derive(Clone)]
#[asn1_obj_selector(prime="1.2.840.10045.1.1",char_two="1.2.840.10045.1.2")]
pub struct X964FieldSelector {
	pub val :Asn1Object,
}

#[derive(Clone)]
#[asn1_choice(selector=fieldType)]
pub struct X9_62_FIELDIDElem {
	pub fieldType :X964FieldSelector,
	pub prime : Asn1BigNum,
	pub char_two :X9_62_CHARACTERISTIC_TWO,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_FIELDID {
	pub elem :Asn1Seq<X9_62_FIELDIDElem>,
}


#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPARAMETERSElem {
	pub version : Asn1Integer,
	pub fieldID : X9_62_FIELDID,
	pub curve :X9_62_CURVE,
	pub base :Asn1OctData,
	pub order :Asn1BigNum,
	pub cofactor : Asn1Opt<Asn1BigNum>,

}


#[asn1_sequence()]
#[derive(Clone)]
pub struct ECPARAMETERS {
	pub elem :Asn1Seq<ECPARAMETERSElem>,
}


#[asn1_int_choice(selector=itype,named_curve=0,parameters=1,implicitCA=2)]
#[derive(Clone)]
pub struct ECPKPARAMETERS {
	pub itype :i32,
	pub named_curve :Asn1Object,
	pub parameters : ECPARAMETERS,
	pub implicitCA : Asn1Null,
}






fn ecprivjsonenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");
	init_log(ns.clone())?;
	if sarr.len() < 1 {
		extargs_new_error!{EcLoadError,"need jsonfile"}
	}

	let jsons = read_file(&sarr[0])?;
	let jval :serde_json::Value = serde_json::from_str(&jsons)?;
	let mut bag :ECPKPARAMETERS = ECPKPARAMETERS::init_asn1();
	let _ = bag.decode_json("",&jval)?;
	let cstr = format!("[{}] format ECPKPARAMETERS\n",sarr[0]);
	let mut outf = std::io::stdout();
	let _ = bag.print_asn1(&cstr,0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = bag.encode_asn1()?;
		write_file_bytes(&output,&code)?;
	}
	Ok(())
}



#[extargs_map_function(ecprivjsonenc_handler)]
pub fn load_ec_parser(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"ecprivjsonenc<ecprivjsonenc_handler>##jsonfile to load ecpriv##" : {{
			"$" : 1
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}