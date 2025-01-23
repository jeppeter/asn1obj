
use proc_macro::TokenStream;
use proc_macro2;
use quote::{ToTokens};

use std::fmt::{Debug};
use std::fmt;
use std::error::Error;
use std::boxed::Box;


use syn;
use std::collections::HashMap;
use lazy_static::lazy_static;

mod consts;
#[macro_use]
mod errors;
#[macro_use]
mod logger;

use crate::logger::*;
use crate::consts::*;

mod randv;

use logger::{asn1_gen_debug_out};
use randv::{get_random_bytes};

struct ProcVar {
	debuglevel :i32,
}



fn asn1_gen_proc_var_init(prefix :&str) -> ProcVar {
	let getv :String;
	let mut dbglvl :i32 = 0;
	let key :String;

	key = format!("{}_DEBUG_LEVEL", prefix);
	getv = _asn1_gen_get_environ_var(&key);
	if getv.len() > 0 {
		match getv.parse::<i32>() {
			Ok(v) => {
				dbglvl = v;
			},
			Err(e) => {
				dbglvl = 0;
				eprintln!("can not parse [{}] error[{}]", getv,e);
			}
		}
	}


	return ProcVar {
		debuglevel : dbglvl,
	};
}



lazy_static! {
	static ref ASN1_GEN_PROC_VAR : ProcVar = {
		asn1_gen_proc_var_init("ASN1_GEN")
	};
}


asn1_gen_error_class!{TypeError}

macro_rules! asn1_syn_error_fmt {
	($($a:expr),*) => {
		let cerr = format!($($a),*);
		asn1_gen_log_error!("{}",cerr);
		return cerr.parse().unwrap();
		//return syn::Error::new(
        //            Span::call_site(),
        //            $cerr,
        //        ).to_compile_error().to_string().parse().unwrap();
    }
}

fn extract_type_name(n :&str) -> String {
	let mut rets :String;
	rets = format!("{}",n);

	let ov = rets.find('<');
	if ov.is_some() {
		let n = ov.unwrap();
		let bytes = rets.as_bytes();
		let mut cnt = n;
		while bytes[cnt]  == 0x3c || bytes[cnt] == 0x20 {
			cnt -= 1;
		}
		rets = rets[0..(cnt+1)].to_string();
	}
	return rets;
}

fn get_name_type(n : syn::Field) -> Result<(String,String), Box<dyn Error>> {
	let name :String ;
	let typename :String ;
	match n.ident {
		Some(ref _i) => {
			name = format!("{}",_i);
		},
		None => {
			asn1_gen_new_error!{TypeError,"can not get"}
		}
	}

	let mut ttks :proc_macro2::TokenStream = proc_macro2::TokenStream::new();
	n.ty.to_tokens(&mut ttks);
	typename = format!("{}",ttks.to_string());

	//asn1_gen_log_trace!("name [{}] typename [{}]",name,typename);
	Ok((name,typename))
}

fn format_tab_line(tabs :i32, c :&str) -> String {
	let mut rets :String = "".to_string();
	for _i in 0..tabs{
		rets.push_str("    ");
	}
	rets.push_str(c);
	rets.push_str("\n");
	rets
}

include!("kv.rs");
include!("asn1ext.rs");

include!("selector.rs");



include!("choice.rs");



include!("seq.rs");



#[proc_macro_attribute]
pub fn asn1_ext(_attr :TokenStream,item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("asn1_ext\n{}",item.to_string());
	item
}
