
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

fn format_tab_line(tabs :i32, c :&str) -> String {
	let mut rets :String = "".to_string();
	for _i in 0..tabs{
		rets.push_str("    ");
	}
	rets.push_str(c);
	rets.push_str("\n");
	rets
}

asn1_gen_error_class!{SelectorSynError}

struct ObjSelectorSyn {
	errname :String,
	sname :String,
	selname : String,
	selmap :HashMap<String,String>,
	kmap :HashMap<String,String>,
}

#[allow(unused_variables)]
#[allow(unused_mut)]
impl ObjSelectorSyn {
	pub fn new() -> Self {
		ObjSelectorSyn {
			sname : "".to_string(),
			errname : "".to_string(),
			selname : "".to_string(),
			selmap : HashMap::new(),
			kmap : HashMap::new(),
		}
	}

	pub fn set_selector(&mut self,k :&str,v :&str) -> Result<(),Box<dyn Error>> {
		self.selname = format!("{}",k);
		self.selmap.insert(format!("{}",k),format!("{}",v));
		Ok(())
	}

	pub fn set_matches(&mut self, k :&str, v :&str) -> Result<(),Box<dyn Error>> {
		self.kmap.insert(format!("{}",k),format!("{}",v));
		Ok(())
	}

	pub fn set_sname(&mut self, k:&str) {
		self.sname = format!("{}",k);
		return;
	}

	fn format_init_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		return rets;
	}

	fn format_decode_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		return rets;
	}

	fn format_encode_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		return rets;
	}

	fn format_print_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		return rets;
	}

	fn format_encode_selector(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		return rets;
	}

	fn format_decode_selector(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		return rets;
	}


	pub fn format_asn1_code(&mut self) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		if self.sname.len() == 0 {
			asn1_gen_new_error!{SelectorSynError,"need set sname"}
		}

		if self.selname.len() == 0 {
			asn1_gen_new_error!{SelectorSynError,"need selname"}
		}

		if self.errname.len() == 0 {
			self.errname = format!("{}Error",self.sname);
			self.errname.push_str("_");
			self.errname.push_str(&get_random_bytes(20));
			rets.push_str(&format_tab_line(0,&format!("asn1obj_error_class!{{ {} }}", self.errname)));
			rets.push_str(&format_tab_line(0,""));
		}

		rets.push_str(&format_tab_line(0,&format!("impl Asn1Op for {} {{", self.sname)));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_init_asn1(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_decode_asn1(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_encode_asn1(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_print_asn1(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&format_tab_line(0,"}"));

		rets.push_str(&format_tab_line(0,""));

		rets.push_str(&format_tab_line(0,&format!("impl Asn1Selector for {} {{", self.sname)));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_encode_selector(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_decode_selector(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&format_tab_line(0,"}"));

		asn1_gen_log_trace!("code\n{}",rets);
		Ok(rets)
	}
}

impl syn::parse::Parse for ObjSelectorSyn {
	fn parse(input :syn::parse::ParseStream) -> syn::parse::Result<Self> {
		let mut retv = ObjSelectorSyn::new();
		let mut k :String = "".to_string();
		let mut v :String = "".to_string();
		let mut iskey :bool = true;
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
					asn1_gen_log_error!("{}",c);
					return Err(syn::Error::new(input.span(),&e));
				}
			} else if input.peek(syn::Token![=]) {
				let _c : syn::token::Eq = input.parse()?;
				asn1_gen_log_trace!("=");
				iskey = false;
			} else if input.peek(syn::Token![,]) {
				let _c : syn::token::Comma = input.parse()?;
				if k.len() == 0 || v.len() == 0 {
					let c = format!("need set k=v format");
					asn1_gen_log_error!("{}",c);
					return Err(syn::Error::new(input.span(),&c));
				}
				let ov = retv.set_matches(&k,&v);
				if ov.is_err() {
					let e = ov.err().unwrap();
					let c = format!("{:?}", e);
					asn1_gen_log_error!("{}",c);
					return Err(syn::Error::new(input.span(),&c));
				}
				iskey = true;
				k = "".to_string();
				v = "".to_string();
			} else if input.peek(syn::Token![.]) {
				let _c : syn::token::Dot = input.parse()?;
				if iskey {
					k.push_str(".");
				} else {
					v.push_str(".");
				}
			} else {
				if input.is_empty() {
					if k.len() != 0 && v.len() != 0 {
						let ov = retv.set_matches(&k,&v);
						if ov.is_err() {
							let e = ov.err().unwrap();
							let c = format!("{:?}", e);
							return Err(syn::Error::new(input.span(),&c));
						}
					} else if v.len() == 0 && k.len() != 0 {
						let c = format!("need value in [{}]",k);
						asn1_gen_log_error!("{}",c);
						return Err(syn::Error::new(input.span(),&c));
					}
					break;
				}
				let c = format!("not valid token [{}]",input.to_string());
				asn1_gen_log_error!("{}",c);
				return Err(syn::Error::new(input.span(),&c));				
			}
		}
		Ok(retv)
	}
}


#[proc_macro_attribute]
pub fn asn1_selector(_attr :TokenStream,item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let nargs = _attr.clone();
	let co :syn::DeriveInput;
	let sname :String;
	asn1_gen_log_trace!(" ");
	let mut selcs :ObjSelectorSyn = syn::parse_macro_input!(nargs as ObjSelectorSyn);

	asn1_gen_log_trace!(" ");
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
	selcs.set_sname(&sname);


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
						let res = selcs.set_selector(&n,&tn);
						if res.is_err() {
							asn1_syn_error_fmt!("{:?}",res.err().unwrap());
						}
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
	
	cc.push_str(&(selcs.format_asn1_code().unwrap()));
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
		} 
		self.parsenames.push(format!("{}", _k));
		self.typemap.insert(format!("{}",_k),format!("{}",_v));		
		return;
	}

	fn foramt_init_asn1(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab,"fn init_asn1() -> Self {"));
		rets.push_str(&format_tab_line(tab + 1,&format!("{} {{",self.sname)));
		for k in self.parsenames.iter() {
			let v = self.typemap.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2,&format!("{} : {}::init_asn1(),", k,v)));
		}
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_decode_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut sidx :usize;
		let mut idx :usize;

		rets.push_str(&format_tab_line(tab,"fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1,"let mut retv :usize = 0;"));
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("retv += self.{}.decode_asn1(code)?;",self.selname)));
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("let k = self.{}.decode_select()?;", self.selname)));

		idx = 0;
		sidx = 0;

		rets.push_str(&format_tab_line(tab + 1,""));
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				if sidx == 0 {
					rets.push_str(&format_tab_line(tab + 1,&format!("if k == \"{}\" {{", self.parsenames[idx])));								
				} else {
					rets.push_str(&format_tab_line(tab + 1,&format!("}} else if k == \"{}\" {{", self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2,&format!("retv += self.{}.decode_asn1(&code[retv..])?;", self.parsenames[idx])));
				sidx += 1;
			}
			idx += 1;
		}

		if sidx > 0 {
			rets.push_str(&format_tab_line(tab + 1,"} else {"));
			rets.push_str(&format_tab_line(tab + 2,&format!("asn1obj_new_error!{{ {}, \"can not find [{{}}] selector\", k}}", self.errname)));
			rets.push_str(&format_tab_line(tab + 1,"}"));
		} else {
			rets.push_str(&format_tab_line(tab + 1,&format!("asn1obj_new_error!{{ {}, \"can not find [{{}}] selector\", k}}", self.errname)));
		}
		rets.push_str(&format_tab_line(tab + 1,""));

		rets.push_str(&format_tab_line(tab + 1,"Ok(retv)"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_encode_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut sidx :usize;
		let mut idx :usize;
		rets.push_str(&format_tab_line(tab,"fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1,"let mut retv : Vec<u8>;"));
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("retv = self.{}.encode_asn1()?;", self.selname)));
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1 ,&format!("let k = self.{}.encode_select()?;",self.selname)));
		sidx = 0;
		idx = 0;
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				if sidx == 0 {
					rets.push_str(&format_tab_line(tab + 1, &format!("if k == \"{}\" {{", self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab + 1, &format!("}} else if k == \"{}\" {{", self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2, &format!("let vk = self.{}.encode_asn1()?;", self.parsenames[idx])));
				rets.push_str(&format_tab_line(tab + 2, "for i in 0..vk.len() {"));
				rets.push_str(&format_tab_line(tab + 3, "retv.push(vk[i]);"));
				rets.push_str(&format_tab_line(tab + 2, "}"));
				sidx += 1;
			}
			idx += 1;
		}

		if sidx > 0 {
			rets.push_str(&format_tab_line(tab + 1, "} else {"));
			rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{ {}, \"can not support [{{}}]\", k }}", self.errname)));
			rets.push_str(&format_tab_line(tab + 1, "}"));
		} else {
			rets.push_str(&format_tab_line(tab + 1, &format!("asn1obj_new_error!{{ {}, \"can not support [{{}}]\", k }}", self.errname)));
		}

		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,"Ok(retv)"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_print_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut sidx :usize;
		let mut idx :usize;
		rets.push_str(&format_tab_line(tab,"fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1,&format!("let k = self.{}.encode_select()?;",self.selname)));
		sidx = 0;
		idx = 0;
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				if sidx == 0 {
					rets.push_str(&format_tab_line(tab + 1,&format!("if k == \"{}\" {{", self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab + 1,&format!("}} else if k == \"{}\" {{", self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2, &format!("let nname = format!(\"{{}}.{}\", name);", self.parsenames[idx])));
				rets.push_str(&format_tab_line(tab + 2, &format!("let _ = self.{}.print_asn1(&nname,tab, iowriter)?;",self.parsenames[idx])));

				sidx += 1;
			}
			idx += 1;
		}
		if sidx > 0 {
			rets.push_str(&format_tab_line(tab + 1, "} else {"));
			rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{ {}, \"can not support [{{}}]\", k }}", self.errname)));
			rets.push_str(&format_tab_line(tab + 1, "}"));
		} else {
			rets.push_str(&format_tab_line(tab + 1, &format!("asn1obj_new_error!{{ {}, \"can not support [{{}}]\", k }}", self.errname)));
		}

		rets.push_str(&format_tab_line(tab + 1,"Ok(())"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	pub fn format_asn1_code(&mut self) -> Result<String, Box<dyn Error>> {
		let mut rets = "".to_string();
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

			rets.push_str(&format_tab_line(0,&format!("asn1obj_error_class!{{ {} }}", self.errname)));
			rets.push_str(&format_tab_line(0,""));
		}



		rets.push_str(&format_tab_line(0,&format!("impl Asn1Op for {} {{", self.sname)));

		/**/
		rets.push_str(&self.foramt_init_asn1(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_decode_asn1(1));
		rets.push_str(&format_tab_line(1,""));		
		rets.push_str(&self.format_encode_asn1(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_print_asn1(1));
		rets.push_str(&format_tab_line(1,""));

		rets.push_str(&format_tab_line(0,"}"));

		asn1_gen_log_trace!("code\n{}",rets);

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

