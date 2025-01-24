
use std::error::Error;
#[allow(unused_imports)]
use crate::*;
use quote::{ToTokens};

asn1_gen_error_class!{UtilError}

pub (crate) fn extract_type_name(n :&str) -> String {
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

pub (crate) fn get_name_type(n : syn::Field) -> Result<(String,String), Box<dyn Error>> {
	let name :String ;
	let typename :String ;
	match n.ident {
		Some(ref _i) => {
			name = format!("{}",_i);
		},
		None => {
			asn1_gen_new_error!{UtilError,"can not get"}
		}
	}

	let mut ttks :proc_macro2::TokenStream = proc_macro2::TokenStream::new();
	n.ty.to_tokens(&mut ttks);
	typename = format!("{}",ttks.to_string());

	//asn1_gen_log_trace!("name [{}] typename [{}]",name,typename);
	Ok((name,typename))
}

pub (crate) fn format_tab_line(tabs :i32, c :&str) -> String {
	let mut rets :String = "".to_string();
	for _i in 0..tabs{
		rets.push_str("    ");
	}
	rets.push_str(c);
	rets.push_str("\n");
	rets
}
