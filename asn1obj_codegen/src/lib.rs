
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

use logger::{asn1_gen_debug_out};

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

#[proc_macro_attribute]
pub fn asn1_selector(attr :TokenStream,item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let co :syn::DeriveInput;
	let sname :String;
	let mut names :HashMap<String,String> = HashMap::new();
	let mut structnames :Vec<String> = Vec::new();

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
    					if tn.contains(KEYWORD_LEFT_ARROW) && tn != KEYWORD_VEC_STRING {
    						asn1_syn_error_fmt!("tn [{}] not valid",tn);
    					}
    					if names.get(&n).is_some() {
    						asn1_syn_error_fmt!("n [{}] has already in",n);
    					}

    					if !check_in_array(ARGSET_KEYWORDS.clone(),&tn) {
    						if !check_in_array(structnames.clone(), &tn) {
	    						asn1_gen_log_trace!("input typename [{}]",tn);
	    						structnames.push(format!("{}",tn));    							
    						}
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


#[proc_macro_attribute]
pub fn asn1_choice(attr :TokenStream,item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let co :syn::DeriveInput;
	let sname :String;
	let mut names :HashMap<String,String> = HashMap::new();
	let mut structnames :Vec<String> = Vec::new();

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
    					if tn.contains(KEYWORD_LEFT_ARROW) && tn != KEYWORD_VEC_STRING {
    						asn1_syn_error_fmt!("tn [{}] not valid",tn);
    					}
    					if names.get(&n).is_some() {
    						asn1_syn_error_fmt!("n [{}] has already in",n);
    					}

    					if !check_in_array(ARGSET_KEYWORDS.clone(),&tn) {
    						if !check_in_array(structnames.clone(), &tn) {
	    						asn1_gen_log_trace!("input typename [{}]",tn);
	    						structnames.push(format!("{}",tn));    							
    						}
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

