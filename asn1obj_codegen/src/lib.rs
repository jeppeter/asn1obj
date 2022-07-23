
use proc_macro::TokenStream;


use std::fmt::{Debug};
use std::fmt;
use std::error::Error;
use std::boxed::Box;


use syn;
use std::collections::HashMap;

#[macro_use]
mod errors;
#[macro_use]
mod logger;

mod randv;

use logger::{asn1_gen_debug_out};
use randv::{get_random_bytes};

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

fn get_name_type(n : syn::Field) -> Result<(String,String), Box<dyn Error>> {
	let name :String ;
	let mut typename :String = "".to_string();
	match n.ident {
		Some(ref _i) => {
			name = format!("{}",_i);
		},
		None => {
			asn1_gen_new_error!{TypeError,"can not get"}
		}
	}

	match n.ty {
		syn::Type::Path(ref _p) => {
			let mut pidx :i32 = 0;
			if _p.path.leading_colon.is_some() {
				typename.push_str("::");
			}
			for _s in _p.path.segments.iter() {
				if pidx > 0 {
					typename.push_str("::");
				}
				typename.push_str(&(format!("{}",_s.ident)));
				//asn1_gen_log_trace!("f [{}]",typename);
				match _s.arguments {
					syn::PathArguments::None => {},
					syn::PathArguments::AngleBracketed(ref _an) => {
						typename.push_str("<");
						let mut idx :i32 = 0;
						for _ii in _an.args.iter() {
							match _ii {
								syn::GenericArgument::Type(ref _pi) => {
									match _pi {
										syn::Type::Path(ref _pt) => {
											let mut jdx : i32 = 0;
											if idx > 0 {
												typename.push_str(",");
											}
											for _tt in _pt.path.segments.iter() {
												if jdx > 0 {
													typename.push_str("::");
												}
												typename.push_str(&(format!("{}", _tt.ident)));
												jdx += 1;
											}
										},
										_ => { asn1_gen_new_error!{TypeError, "not "}}
									}
								},
								_ => {
									asn1_gen_new_error!{TypeError,"no args type"}
								}
							}
							idx += 1;
						}
						typename.push_str(">");
					},
					syn::PathArguments::Parenthesized(ref _pn) => {
						asn1_gen_new_error!{TypeError,"Parenthesized"}
					}
				}
				pidx += 1;
			}
		},
		_ => {
			asn1_gen_new_error!{TypeError,"ty not support for"}
		}
	}
	asn1_gen_log_trace!("name [{}] typename [{}]",name,typename);
	Ok((name,typename))
}

macro_rules!  format_tab_line {
	($tab:expr,$($a:tt)+) => {
		let _maxtab : usize = ($tab) as usize;
		let mut _c :String = "".to_string();
		for _i in 0.._maxtab{
			_c.push_str("    ");
		}
		_c.push_str(&format!($($arg)+));
		_c
	}
}


#[proc_macro_attribute]
pub fn asn1_selector(_attr :TokenStream,item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let co :syn::DeriveInput;
	let sname :String;
	let mut names :HashMap<String,String> = HashMap::new();

	match syn::parse::<syn::DeriveInput>(item.clone()) {
		Ok(v) => {
			co = v.clone();
		},
		Err(_e) => {
			asn1_syn_error_fmt!("not parse \n{}",item.to_string());
        }
    }

    sname = format!("{}",co.ident);
    asn1_gen_log_trace!("sname [{}]",sname);


    match co.data {
    	syn::Data::Struct(ref _vv) => {
    		match _vv.fields {
    			syn::Fields::Named(ref _n) => {
    				for _v in _n.named.iter() {
    					let res = get_name_type(_v.clone());
    					if res.is_err() {
    						asn1_syn_error_fmt!("{:?}",res.err().unwrap());
    					}
    					let (n,tn) = res.unwrap();
    					if names.get(&n).is_some() {
    						asn1_syn_error_fmt!("n [{}] has already in",n);
    					}
    					names.insert(format!("{}",n),format!("{}",tn));
    				}
    			},
    			_ => {
    				asn1_syn_error_fmt!("not Named structure\n{}",item.to_string());
    			}
    		}
    	},
    	_ => {
    		asn1_syn_error_fmt!("not struct format\n{}",item.to_string());
    	}
    }

    /*now to compile ok*/
    //let cc = format_code(&sname,names.clone(),structnames.clone());
    let cc = item.to_string();

    cc.parse().unwrap()
}

struct ChoiceSyn {
	sname : String,
	selname :String,
	errname :String,
	parsenames :Vec<String>,
	typemap :HashMap<String,String>,
}

asn1_gen_error_class!{ChoiceSynError}

impl ChoiceSyn {

	pub fn new() -> Self {
		ChoiceSyn{
			sname : "".to_string(),
			selname : "".to_string(),
			errname : "".to_string(),
			parsenames : Vec::new(),
			typemap : HashMap::new(),
		}
	}

	pub fn set_attr_name(&mut self, k :&str, v :&str) -> Result<(),Box<dyn Error>> {
		if k == "error" {
			self.errname = format!("{}",v);
		} else if k == "selector" {
			self.selname = format!("{}",v);
		} else {
			asn1_gen_new_error!{ChoiceSynError,"not valid [{}] only accept error or selector", k}
		}
		Ok(())
	}

	pub fn set_struct_name(&mut self, k :&str) {
		self.sname = format!("{}",k);
		return;
	}

	pub fn set_name(&mut self,_k :&str,_v :&str) {
		if _k == "selector"  {
			if self.selname.len() == 0 {
				self.selname = format!("{}",_k);
			}
		} else {
			self.parsenames.push(format!("{}", _k));
			self.typemap.insert(format!("{}",_k),format!("{}",_v));
		}
		return;
	}

	pub fn format_asn1_code(&mut self) -> Result<String, Box<dyn Error>> {
		let rets = "".to_string();
		if self.sname.len() == 0 {
			asn1_gen_new_error!{ChoiceSynError,"need sname set"}
		} else if self.selname.len() == 0 {
			asn1_gen_new_error!{ChoiceSynError,"need selector name"}
		}

		if self.errname.len() == 0 {
			self.errname = format!("{}Error", self.sname);
			self.errname.push_str("_");
			self.errname.push_str(&get_random_bytes(20));
			asn1_gen_log_trace!("errname [{}]",self.errname);
		}


		Ok(rets)
	}
}


impl syn::parse::Parse for ChoiceSyn {
	fn parse(input :syn::parse::ParseStream) -> syn::parse::Result<Self> {
		let mut retv = ChoiceSyn::new();
		let mut k :String = "".to_string();
		let mut v :String = "".to_string();
		loop {
			if input.peek(syn::Ident) {
				let c :syn::Ident = input.parse()?;
				asn1_gen_log_trace!("token [{}]",c);
				if k.len() == 0 {
					k = format!("{}",c);
				} else if v.len() == 0 {
					v = format!("{}",c);
				} else {
					let e = format!("only accept k=v format");
					return Err(syn::Error::new(input.span(),&e));
				}
			} else if input.peek(syn::Token![=]) {
				let _c : syn::token::Eq = input.parse()?;
				asn1_gen_log_trace!("=");
			} else if input.peek(syn::Token![,]) {
				let _c : syn::token::Comma = input.parse()?;
				if k.len() == 0 || v.len() == 0 {
					let c = format!("need set k=v format");
					return Err(syn::Error::new(input.span(),&c));
				}
				let ov = retv.set_attr_name(&k,&v);
				if ov.is_err() {
					let e = ov.err().unwrap();
					let c = format!("{:?}", e);
					return Err(syn::Error::new(input.span(),&c));
				}
			} else {
				if input.is_empty() {
					if k.len() != 0 && v.len() != 0 {
						let ov = retv.set_attr_name(&k,&v);
						if ov.is_err() {
							let e = ov.err().unwrap();
							let c = format!("{:?}", e);
							return Err(syn::Error::new(input.span(),&c));
						}
					} else if v.len() == 0 && k.len() != 0 {
						let c = format!("need value in [{}]",k);
						return Err(syn::Error::new(input.span(),&c));
					}
					break;
				}
				let c = format!("not valid token [{}]",input.to_string());
				return Err(syn::Error::new(input.span(),&c));				
			}
		}
		Ok(retv)
	}
}


#[proc_macro_attribute]
pub fn asn1_choice(_attr :TokenStream,item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let co :syn::DeriveInput;
	let nargs = _attr.clone();
	let sname :String;
	let mut cs :ChoiceSyn = syn::parse_macro_input!(nargs as ChoiceSyn);

	match syn::parse::<syn::DeriveInput>(item.clone()) {
		Ok(v) => {
			co = v.clone();
		},
		Err(_e) => {
			asn1_syn_error_fmt!("not parse \n{}",item.to_string());
        }
    }

    sname = format!("{}",co.ident);
    asn1_gen_log_trace!("sname [{}]",sname);
    cs.set_struct_name(&sname);


    match co.data {
    	syn::Data::Struct(ref _vv) => {
    		match _vv.fields {
    			syn::Fields::Named(ref _n) => {
    				for _v in _n.named.iter() {
    					let res = get_name_type(_v.clone());
    					if res.is_err() {
    						asn1_syn_error_fmt!("{:?}",res.err().unwrap());
    					}
    					let (n,tn) = res.unwrap();
    					cs.set_name(&n,&tn);
    				}
    			},
    			_ => {
    				asn1_syn_error_fmt!("not Named structure\n{}",item.to_string());
    			}
    		}
    	},
    	_ => {
    		asn1_syn_error_fmt!("not struct format\n{}",item.to_string());
    	}
    }

    /*now to compile ok*/
    //let cc = format_code(&sname,names.clone(),structnames.clone());
    let mut cc = item.to_string();
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    cc.parse().unwrap()
}

