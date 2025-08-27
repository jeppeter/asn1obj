
#[allow(unused_imports)]
use crate::*;
use crate::logger::{asn1_gen_debug_out};
use crate::kv::{SynKV};
use crate::consts::*;
use std::error::Error;
use crate::utils::{get_name_type};
use quote::ToTokens;


asn1_gen_error_class!{Asn1ExtError}

fn _get_synkv(ntoks :proc_macro::TokenStream) -> Result<SynKV,Box<dyn Error>> {
	let ores = syn::parse::<SynKV>(ntoks);
	if ores.is_err() {
		asn1_gen_new_error!{Asn1ExtError,"not parse synkv"}
	}
	Ok(ores.unwrap())
}

pub (crate) fn filter_attrib(_v :&mut syn::Field) -> Result<(String,String,SynKV),Box<dyn Error>> {
	let mut retv :SynKV = SynKV::new();
	let n :String;
	let tn :String;
	let res = get_name_type(_v.clone());
	if res.is_err() {
		asn1_gen_new_error!{Asn1ExtError,"{:?}",res.err().unwrap()}
	}
	(n,tn) = res.unwrap();
	asn1_gen_log_trace!("[{}]=[{}]",n,tn);
	let mut removed :Vec<usize> = vec![];
	let mut idx:usize = 0;
	while idx < _v.attrs.len() {
		let _a = &_v.attrs[idx];

		let v = format!("{}",_a.path().get_ident().as_ref().unwrap());
		if v == ASN1_EXTMACRO {
			removed.push(idx);
			asn1_gen_log_trace!("[{}]=[{}][{}]",n,v,_a.meta.to_token_stream().to_string());



			//let ntoks =proc_macro::TokenStream::from(_a.meta.clone());
			let ntoks = proc_macro::TokenStream::from(_a.meta.to_token_stream());
			let kv :SynKV = _get_synkv(ntoks)?;
			for k in kv.get_keys().iter() {
				let ov = kv.get_value(k).unwrap();
				retv.set_attr(k,&ov).unwrap();
			}
		}
		idx += 1;
	}

	if removed.len() > 0 {
		idx = removed.len() - 1;
		loop {
			_v.attrs.remove(removed[idx]);
			if idx == 0 {
				break;
			}
			idx -= 1;
		}
	}

	return Ok((n,tn,retv));
}


pub (crate) fn filter_serde(_v :&mut syn::Field) -> Result<SynKV,Box<dyn Error>> {
	let mut retv :SynKV = SynKV::new();
	let mut removed :Vec<usize> = vec![];
	let mut idx:usize = 0;
	let n :String;
	let res = get_name_type(_v.clone());
	if res.is_err() {
		asn1_gen_new_error!{Asn1ExtError,"{:?}",res.err().unwrap()}
	}
	(n,_) = res.unwrap();
	while idx < _v.attrs.len() {
		let _a = &_v.attrs[idx];

		let v = format!("{}",_a.path().get_ident().as_ref().unwrap());
		if v == SERDE_IDENT {
			removed.push(idx);
			asn1_gen_log_trace!("[{}]=[{}][{}]",n,v,_a.meta.to_token_stream().to_string());

			let ntoks =proc_macro::TokenStream::from(_a.meta.to_token_stream());
			let kv :SynKV = _get_synkv(ntoks)?;
			for k in kv.get_keys().iter() {
				let ov = kv.get_value(k).unwrap();
				asn1_gen_log_trace!("[{}]=[{}]",k,ov);
				retv.set_attr(k,&ov).unwrap();
			}
		}
		idx += 1;
	}

	if removed.len() > 0 {
		idx = removed.len() - 1;
		loop {
			asn1_gen_log_trace!("remove attr {} [{}]",idx,_v.attrs[removed[idx]].meta.to_token_stream().to_string());
			_v.attrs.remove(removed[idx]);
			if idx == 0 {
				break;
			}
			idx -= 1;
		}
	}
	return Ok(retv);	
}

pub (crate) fn asn1_ext(_attr :proc_macro::TokenStream,item :proc_macro::TokenStream) -> proc_macro::TokenStream {
	asn1_gen_log_trace!("asn1_ext\n{}",item.to_string());
	item
}

pub (crate) fn get_attr_clone_serde(inval :&syn::DeriveInput) -> Result<(bool,bool,bool),Box<dyn Error>> {
	let mut isclone:bool = false;
	let mut isserialize:bool = false;
	let mut isdeserialize :bool = false;
	for _a in &inval.attrs {
		match _a.style {
			syn::AttrStyle::Inner(ref _a) => {
				continue;
			},
			_ => {

			},
		}

		isclone= true;
		isserialize = true;
		isdeserialize = true;



	}

	Ok((isclone,isserialize,isdeserialize))
}
