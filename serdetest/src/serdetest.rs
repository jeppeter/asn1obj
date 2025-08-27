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

use serde::{Serialize,Deserialize,de::DeserializeOwned};

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




extargs_error_class!{JsonLoadError}


#[derive(Clone,Debug,Serialize,Deserialize)]
enum DeriveEnum {
	Enum1,
	Enum3,
	EnumCC,
}



impl TryFrom<i32> for DeriveEnum {
	type Error = String;

	fn try_from(v :i32)	 -> Result<Self,Self::Error> {
		match v {
			0 => {return Ok(DeriveEnum::Enum1);},
			1 => {return Ok(DeriveEnum::Enum3);},
			2 => {return Ok(DeriveEnum::EnumCC);},
			_ => {return Err(format!("not valid value {}",v));},
		}
	}
}

impl Into<i32> for DeriveEnum {
	fn into(self) -> i32 {
		match self {
			DeriveEnum::Enum1 => {return 0;},
			DeriveEnum::Enum3 => {return 1;},
			DeriveEnum::EnumCC => {return 2;},
		}
	}
}


//#[derive(Debug,Clone)]
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
struct BaseStruct {
	pub name2 :Vec<String>,
	pub cc2 :Vec<i32>,
}

//#[derive(Debug,Clone)]
#[derive(Clone,Debug,Serialize,Deserialize)]
struct NoPatternStruct {
	pub name :Vec<String>,
	pub cc :Vec<i32>,
}

impl Default for NoPatternStruct {
	fn default() -> Self {
		Self {
			name :vec![],
			cc :vec![],
		}
	}
}


//#[derive(Debug,Clone)]
#[allow(non_snake_case)]
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
struct DeriveStruct {
	pub basenew :Vec<BaseStruct>,
	pub pattern :NoPatternStruct,
	pub enumval :DeriveEnum,
}





fn serdeload_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");

	init_log(ns.clone())?;

	if sarr.len() < 1 {
		extargs_new_error!{JsonLoadError,"need binfile"}
	}

	for f in sarr.iter() {
		let s = read_file(f)?;
		let pat :DeriveStruct = serde_json::from_str(&s)?;
		println!("{:?}",pat);

		let outs = serde_json::to_string_pretty(&pat)?;
		println!("outs\n{}",outs);
	}

	Ok(())
}




#[extargs_map_function(serdeload_handler)]
pub fn load_serde_command(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"serdeload<serdeload_handler>##jsonfile ... to load ##" : {{
			"$" : "+"
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}