use std::collections::HashMap;
use std::error::Error;
#[allow(unused_imports)]
use crate::*;
use crate::logger::{asn1_gen_debug_out};

pub (crate) struct SynKV {
	kmap :HashMap<String,String>,
}

impl SynKV {
	pub fn new() -> Self {
		Self {
			kmap :HashMap::new(),
		}
	}

	pub fn set_attr(&mut self,k :&str, v:&str) -> Result<(),Box<dyn Error>> {
		self.kmap.insert(format!("{}",k),format!("{}",v));
		Ok(())
	}

	pub fn get_value(&self,k :&str) -> Option<String> {
		match self.kmap.get(k) {
			Some(_v) => {
				return Some(format!("{}",_v));
			},
			_ => {
				return None;
			}
		}
	}

	pub fn get_keys(&self) -> Vec<String> {
		let mut retv :Vec<String> = vec![];
		for (k,_) in self.kmap.iter() {
			retv.push(format!("{}",k));
		}
		retv
	}
}

impl syn::parse::Parse for SynKV {
	fn parse(input :syn::parse::ParseStream) -> syn::parse::Result<Self> {
		let mut retv = SynKV::new();
		let mut k :String = "".to_string();
		let mut v :String = "".to_string();
		asn1_gen_log_trace!("enter parse SynKV [{}]",input.to_string());
		loop {
			if input.peek(syn::Ident) {
				let c :syn::Ident = input.parse()?;
				//asn1_gen_log_trace!("token [{}]",c);
				if k.len() == 0 {
					k = format!("{}",c);
				} else if v.len() == 0 {
					v = format!("{}",c);
				} else {
					let e = format!("only accept k=v format");
					return Err(syn::Error::new(input.span(),&e));
				}
			} else if input.peek(syn::Token![=])  {
				let _c : syn::token::Eq = input.parse()?;
				//asn1_gen_log_trace!("=");
			} else if input.peek(syn::Token![,]) {
				let _c : syn::token::Comma = input.parse()?;
				//asn1_gen_log_trace!("parse ,");
				if k.len() == 0 || v.len() == 0 {
					let c = format!("need set k=v format");
					return Err(syn::Error::new(input.span(),&c));
				}
				let ov = retv.set_attr(&k,&v);
				if ov.is_err() {
					let e = ov.err().unwrap();
					let c = format!("{:?}", e);
					return Err(syn::Error::new(input.span(),&c));
				}
				//asn1_gen_log_trace!("parse [{}]=[{}]",k,v);
				k = "".to_string();
				v = "".to_string();
			} else if input.peek(syn::token::Paren)  {
				let ntoks ;
				let _c = syn::parenthesized!(ntoks in input);
				//let ctoken :TokenStream = ntoks.to_string().parse().unwrap();
				let innerkv :SynKV = ntoks.parse()?;
				asn1_gen_log_trace!("after parenthesized");

				// //let toks = ntoks.to_token_stream();

				//let innerkv :SynKV= syn::parse_macro_input!(toks as SynKV);
				let ks = innerkv.get_keys();
				for ik in ks.iter() {
					let oiv = innerkv.get_value(ik);
					if oiv.is_some() {
						retv.set_attr(ik,oiv.as_ref().unwrap()).unwrap();
					}
				}
				asn1_gen_log_trace!("before ntoks [{}]",input.to_string());
			} else if input.peek(syn::LitStr) {
				let c :syn::LitStr = input.parse()?;
				if k.len() == 0 {
					k.push_str(&format!("{}",c.value()));
				} else {
					v = format!("{}",c.value());
					let ov = retv.set_attr(&k,&v);
					if ov.is_err() {
						let e = ov.err().unwrap();
						let c = format!("{:?}", e);
						asn1_gen_log_error!("{}",c);
						return Err(syn::Error::new(input.span(),&c));
					}
				}

			} else {
				if input.is_empty() {
					break;
				}
				let c = format!("[{}:{}]not valid token [{}]",file!(),line!(),input.to_string());
				return Err(syn::Error::new(input.span(),&c));
			}
		}
		if k.len() != 0 && v.len() != 0 {
			retv.set_attr(&k,&v).unwrap();
		} else if v.len() == 0 && k.len() != 0 {
			retv.set_attr(&k,"").unwrap();
		}
		asn1_gen_log_trace!("exit parse SynKV keys [{:?}]",retv.get_keys());
		Ok(retv)
	}
}
