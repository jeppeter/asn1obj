
use proc_macro::TokenStream;
use proc_macro2;
use quote::{ToTokens};

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

fn extract_type_name(n :&str) -> String {
	let mut rets :String;
	rets = format!("{}",n);

	let ov = rets.find('<');
	if ov.is_some() {
		let n = ov.unwrap();
		rets = rets[0..n].to_string();
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


asn1_gen_error_class!{SelectorSynError}

//struct TypeSelectorSyn {
//	parsenames :Vec<String>,
//	parsemap :HashMap<String,String>,
//}

struct ObjSelectorSyn {
	defname :String,
	debugenable : bool,
	errname :String,
	sname :String,
	selname : String,
	parsenames : Vec<String>,
	parsemap : HashMap<String,String>,
	kmap :HashMap<String,Vec<String>>,
}

//#[allow(unused_variables)]
//#[allow(unused_mut)]
impl ObjSelectorSyn {
	pub fn new() -> Self {
		ObjSelectorSyn {
			defname :"".to_string(),
			debugenable : false,
			sname : "".to_string(),
			errname : "".to_string(),
			selname : "".to_string(),
			parsenames : Vec::new(),
			parsemap : HashMap::new(),
			kmap : HashMap::new(),
		}
	}

	pub fn set_member(&mut self,k :&str, v :&str) -> Result<(),Box<dyn Error>> {
		self.parsenames.push(format!("{}",k));
		self.parsemap.insert(format!("{}",k),format!("{}",v));
		Ok(())
	}

	pub fn set_matches(&mut self, k :&str, v :&str) -> Result<(),Box<dyn Error>> {
		//asn1_gen_log_trace!("k [{}] v [{}]",k,v);
		if k == "selector" {
			self.selname = format!("{}",v);
		} else if v == "default" {
			self.defname = format!("{}",k);
		} else if k == "debug" {
			if v == "enable" {
				self.debugenable = true;
			} else {
				self.debugenable = false;
			}
		} else {
			let ov = self.kmap.get(k);
			let mut insertv :Vec<String>;
			if ov.is_some() {
				insertv = ov.unwrap().clone();
			} else {
				insertv = Vec::new();
			}
			insertv.push(format!("{}",v));
			self.kmap.insert(format!("{}",k),insertv);
		}
		
		Ok(())
	}

	pub fn set_sname(&mut self, k:&str) {
		self.sname = format!("{}",k);
		return;
	}

	fn format_init_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn init_asn1() -> Self {"));
		rets.push_str(&format_tab_line(tab + 1, &format!("{} {{",self.sname)));
		for k in self.parsenames.iter() {
			let v = self.parsemap.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2, &format!("{} : {}::init_asn1(),", k,extract_type_name(v))));
		}
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_decode_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let mut retv :usize = 0;"));
		rets.push_str(&format_tab_line(tab + 1, "let mut _endsize :usize = code.len();"));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _lastv :usize = 0;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _i :usize;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _lasti :usize;"));
		}
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "_lastv = retv;"));
		}
		for k in self.parsenames.iter() {			
			rets.push_str(&format_tab_line(tab + 1, ""));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1, &format!("_outs = format!(\"decode {}.{} will decode at {{}}\\n\",retv);",self.sname,k)));
				rets.push_str(&format_tab_line(tab + 1, "let _ = _outf.write(_outs.as_bytes())?;"));
			}
			rets.push_str(&format_tab_line(tab + 1, &format!("let ro = self.{}.decode_asn1(&code[retv.._endsize]);",k)));
			rets.push_str(&format_tab_line(tab + 1, "if ro.is_err() {"));
			rets.push_str(&format_tab_line(tab + 2, &format!("let e = ro.err().unwrap();")));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 2, &format!("_outs = format!(\"decode {}.{} error {{:?}}\",e);",self.sname,k)));
				rets.push_str(&format_tab_line(tab + 2,"let _ = _outf.write(_outs.as_bytes())?;"));
			}
			rets.push_str(&format_tab_line(tab + 2, "return Err(e);"));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1, &format!("_lastv = retv;")));	
			}
			rets.push_str(&format_tab_line(tab + 1, &format!("retv += ro.unwrap();")));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1,&format!("_outs = format!(\"decode {}.{} retv {{}} _lastv {{}}\",retv,_lastv);",self.sname,k)));
				rets.push_str(&format_tab_line(tab + 1,"_i = 0;"));
				rets.push_str(&format_tab_line(tab + 1,"_lasti = 0;"));
				rets.push_str(&format_tab_line(tab + 1,"while _i < (retv - _lastv) {"));
				rets.push_str(&format_tab_line(tab + 2,"if (_i % 16) == 0 {"));
				rets.push_str(&format_tab_line(tab + 3,"if _i > 0 {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\"    \");"));
				rets.push_str(&format_tab_line(tab + 4,"while _lasti != _i {"));
				rets.push_str(&format_tab_line(tab + 5,"if code[(_lastv + _lasti)] >= 0x20 && code[(_lastv + _lasti)] <= 0x7e {"));
				rets.push_str(&format_tab_line(tab + 6,"_outs.push(code[(_lastv+_lasti)] as char);"));
				rets.push_str(&format_tab_line(tab + 5,"} else {"));
				rets.push_str(&format_tab_line(tab + 6,"_outs.push_str(\".\");"));
				rets.push_str(&format_tab_line(tab + 5,"}"));
				rets.push_str(&format_tab_line(tab + 5,"_lasti += 1;"));
				rets.push_str(&format_tab_line(tab + 4,"}"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"_outs.push_str(&format!(\"\\n0x{:08x}:\",_i));"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 2,"_outs.push_str(&format!(\" 0x{:02x}\", code[_lastv + _i]));"));
				rets.push_str(&format_tab_line(tab + 2,"_i += 1;"));
				rets.push_str(&format_tab_line(tab + 1,"}"));
				rets.push_str(&format_tab_line(tab + 1,"if _lasti != _i {"));
				rets.push_str(&format_tab_line(tab + 2,"while (_i % 16) != 0 {"));
				rets.push_str(&format_tab_line(tab + 3,"_outs.push_str(\"     \");"));
				rets.push_str(&format_tab_line(tab + 3,"_i += 1;"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 2,"_outs.push_str(\"    \");"));
				rets.push_str(&format_tab_line(tab + 2,"while _lasti < (retv - _lastv) {"));
				rets.push_str(&format_tab_line(tab + 3,"if code[(_lastv + _lasti)] >= 0x20 && code[(_lastv + _lasti)] <= 0x7e {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push(code[(_lastv+_lasti)] as char);"));
				rets.push_str(&format_tab_line(tab + 3,"} else {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\".\");"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"_lasti += 1;"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 1,"}"));
				rets.push_str(&format_tab_line(tab + 1,"_outs.push_str(\"\\n\");"));
				rets.push_str(&format_tab_line(tab + 1,"let _ = _outf.write(_outs.as_bytes())?;"));
			}
		}


		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, &format!("_outs = format!(\"{} total {{}}\\n\",retv);", self.sname)));
			rets.push_str(&format_tab_line(tab + 1, "let _ = _outf.write(_outs.as_bytes())?;"));
		}

		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab + 1, "Ok(retv)"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;		
	}

	fn format_encode_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let mut _v8 :Vec<u8> = Vec::new();"));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
		}
		if self.parsenames.len() > 1 {
			rets.push_str(&format_tab_line(tab + 1, "let mut encv :Vec<u8>;"));	
		} else {
			rets.push_str(&format_tab_line(tab + 1, "let encv :Vec<u8>;"));
		}


		
		for k in self.parsenames.iter() {
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, &format!("encv = self.{}.encode_asn1()?;",k)));
			rets.push_str(&format_tab_line(tab + 1, "for i in 0..encv.len() {"));
			rets.push_str(&format_tab_line(tab + 2, "_v8.push(encv[i]);"));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1,""));
				rets.push_str(&format_tab_line(tab + 1,&format!("_outs = format!(\"format {}.{} {{:?}}\\n\",encv);", self.sname, k)));
				rets.push_str(&format_tab_line(tab + 1,"_outf.write(_outs.as_bytes())?;"));
			}
		}


		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab + 1, "Ok(_v8)"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_print_asn1(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {"));
		if self.parsenames.len() == 0 {
			rets.push_str(&format_tab_line(tab + 1, "let s :String;"));
		} else {
			rets.push_str(&format_tab_line(tab + 1, "let mut s :String;"));
		}
		rets.push_str(&format_tab_line(tab + 1, &format!("s = asn1_format_line(tab,&format!(\"{{}} {}\", name));", self.sname)));
		rets.push_str(&format_tab_line(tab + 1, "iowriter.write(s.as_bytes())?;"));
		
		rets.push_str(&format_tab_line(tab + 1, ""));
		for k in self.parsenames.iter() {
			rets.push_str(&format_tab_line(tab + 1, &format!("s = format!(\"{}\");", k)));
			rets.push_str(&format_tab_line(tab + 1, &format!("self.{}.print_asn1(&s,tab + 1, iowriter)?;",k)));
			rets.push_str(&format_tab_line(tab + 1, ""));
		}

		rets.push_str(&format_tab_line(tab + 1, "Ok(())"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn foramt_select_func(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut sidx :usize = 0;
		//let mut idx :usize = 0;
		rets.push_str(&format_tab_line(tab+1,&format!("let k = format!(\"{{}}\",self.{}.get_value());",self.selname)));
		rets.push_str(&format_tab_line(tab + 1, "let retv :String;"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		for (k,v) in self.kmap.iter() {
			if !self.selname.eq(k)  {
				let mut c :String = "".to_string();
				let mut didx :usize ;
				if sidx == 0 {
					c.push_str("if ");
				} else {
					c.push_str("} else if ");
				}
				didx = 0;
				for vs in v.iter() {
					if didx > 0 {
						c.push_str(" || ");
					}
					c.push_str(&format!("k == \"{}\"", vs));
					didx += 1;
				}
				c.push_str(" {");
				rets.push_str(&format_tab_line(tab + 1, &c));
				rets.push_str(&format_tab_line(tab + 2, &format!("retv = format!(\"{}\");",k)));
				sidx += 1;
			}
			//idx += 1;
		}

		if sidx > 0 {
			rets.push_str(&format_tab_line(tab + 1, "} else {"));
			if self.defname.len() == 0 {
				rets.push_str(&format_tab_line(tab + 2,&format!("asn1obj_new_error!{{ {} , \"not support [{{}}]\",k}}",self.errname)));
			} else {
				rets.push_str(&format_tab_line(tab + 2,&(format!("retv = format!(\"{}\");",self.defname))));
			}
			rets.push_str(&format_tab_line(tab + 1, "}"));

		} else {
			if self.defname.len() == 0 {
				rets.push_str(&format_tab_line(tab + 1,&format!("asn1obj_new_error!{{ {} , \"not support [{{}}]\",k}}",self.errname)));	
			} else {
				rets.push_str(&format_tab_line(tab + 2,&(format!("retv = format!(\"{}\");",self.defname))));
			}
			
		}
		rets.push_str(&format_tab_line(tab + 1, "Ok(retv)"));
		return rets;
	}

	fn format_encode_selector(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab,"fn encode_select(&self) -> Result<String,Box<dyn Error>> {"));
		rets.push_str(&self.foramt_select_func(tab));
		rets.push_str(&format_tab_line(tab,"}"));

		return rets;
	}

	fn format_decode_selector(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab,"fn decode_select(&self) -> Result<String,Box<dyn Error>> {"));
		rets.push_str(&self.foramt_select_func(tab));
		rets.push_str(&format_tab_line(tab,"}"));

		return rets;
	}


	pub fn format_asn1_code(&mut self) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		if self.sname.len() == 0 {
			asn1_gen_new_error!{SelectorSynError,"need set sname"}
		}

		if self.selname.len() == 0 {
			if self.parsenames.len() > 0 {
				self.selname =format!("{}",self.parsenames[0]);
			}
			if self.selname.len() == 0 {
				asn1_gen_new_error!{SelectorSynError,"need selname"}	
			}			
		}

		if self.errname.len() == 0 {
			self.errname = format!("{}Error",self.sname);
			self.errname.push_str(&get_random_bytes(20));
			rets.push_str(&format_tab_line(0,&format!("asn1obj_error_class!{{ {} }}", self.errname)));
			rets.push_str(&format_tab_line(0,""));
		}

		rets.push_str(&format_tab_line(0,&format!("impl Asn1Selector for {} {{", self.sname)));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_encode_selector(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_decode_selector(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&format_tab_line(0,"}"));

		rets.push_str(&format_tab_line(0,""));

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


		//asn1_gen_log_trace!("code\n{}",rets);
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
				if iskey {
					k.push_str(&format!("{}",c));
				} else {
					v = format!("{}",c);
					let ov = retv.set_matches(&k,&v);
					if ov.is_err() {
						let e = ov.err().unwrap();
						let c = format!("{:?}", e);
						asn1_gen_log_error!("{}",c);
						return Err(syn::Error::new(input.span(),&c));
					}
				}
			} else if input.peek(syn::LitStr) {
				let c :syn::LitStr = input.parse()?;
				if iskey {
					k.push_str(&format!("{}",c.value()));
				} else {
					v = format!("{}",c.value());
					let ov = retv.set_matches(&k,&v);
					if ov.is_err() {
						let e = ov.err().unwrap();
						let c = format!("{:?}", e);
						asn1_gen_log_error!("{}",c);
						return Err(syn::Error::new(input.span(),&c));
					}
				}

			} else if input.peek(syn::token::Bracket) {
				let con ;
				if iskey {
					let c = format!("need must set after =");
					asn1_gen_log_error!("{}",c);
					return Err(syn::Error::new(input.span(),&c));					
				}

				let _c = syn::bracketed!(con in input);
				asn1_gen_log_trace!("con [{}]",con.to_string());
				while !con.is_empty() {
					let ex : syn::Expr = con.parse()?;
					match ex {
						syn::Expr::Lit(_v) => { 
							asn1_gen_log_trace!("Lit"); 
							match _v.lit {
								syn::Lit::Str(_vv) => {
									v = format!("{}",_vv.value());
									let ov = retv.set_matches(&k,&v);
									if ov.is_err() {
										let e = ov.err().unwrap();
										let c = format!("{:?}",e);
										asn1_gen_log_error!("{}",c);
										return Err(syn::Error::new(input.span(),&c));							
									}
								},
								_ => {
									let c = format!("not litstr or ");
									asn1_gen_log_error!("{}",c);
									return Err(syn::Error::new(input.span(),&c));
								},
							}
						},	
						syn::Expr::Path(_v) => { 
							let mut ttks : proc_macro2::TokenStream = proc_macro2::TokenStream::new();
							_v.to_tokens(&mut ttks);
							asn1_gen_log_trace!("Path"); 
							v = format!("{}",ttks.to_string());
							let ov = retv.set_matches(&k,&v);
							if ov.is_err() {
								let e = ov.err().unwrap();
								let c = format!("{:?}",e);
								asn1_gen_log_error!("{}",c);
								return Err(syn::Error::new(input.span(),&c));							
							}
						},
						_ => {
							let c = format!("not litstr or ");
							asn1_gen_log_error!("{}",c);
							return Err(syn::Error::new(input.span(),&c));							
						}
					}
					if ! con.is_empty() {
						if !con.peek(syn::token::Comma) {
							let c = format!("not comma");
							asn1_gen_log_error!("{}",c);
							return Err(syn::Error::new(input.span(),&c));							
						}
						let _c : syn::token::Comma = con.parse()?;
					}
				}
			} else if input.peek(syn::Token![=]) {
				let _c : syn::token::Eq = input.parse()?;
				iskey = false;
			} else if input.peek(syn::Token![,]) {
				let _c : syn::token::Comma = input.parse()?;
				if k.len() == 0 || v.len() == 0 {
					let c = format!("need set k=v format");
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
pub fn asn1_obj_selector(_attr :TokenStream,item :TokenStream) -> TokenStream {
	//asn1_gen_log_trace!("item\n{}",item.to_string());
	let nargs = _attr.clone();
	let co :syn::DeriveInput;
	let sname :String;
	let mut selcs :ObjSelectorSyn = syn::parse_macro_input!(nargs as ObjSelectorSyn);

	match syn::parse::<syn::DeriveInput>(item.clone()) {
		Ok(v) => {
			co = v.clone();
		},
		Err(_e) => {
			asn1_syn_error_fmt!("not parse \n{}",item.to_string());
		}
	}

	sname = format!("{}",co.ident);
	//asn1_gen_log_trace!("sname [{}]",sname);
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
						let res = selcs.set_member(&n,&tn);
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
    cc.push_str("\n");
    cc.push_str(&(selcs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}

struct ChoiceSyn {
	debugenable : bool,
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
			debugenable : false,
			sname : "".to_string(),
			selname : "".to_string(),
			errname : "".to_string(),
			parsenames : Vec::new(),
			typemap : HashMap::new(),
		}
	}

	pub fn set_attr_name(&mut self, k :&str, v :&str) -> Result<(),Box<dyn Error>> {
		if k == "errorhandler" {
			self.errname = format!("{}",v);
		} else if k == "selector" {
			self.selname = format!("{}",v);
		} else if k == "debug" && (v == "enable" || v == "disable") {
			if v == "enable" {
				self.debugenable = true;
			} else {
				self.debugenable = false;
			}
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
			rets.push_str(&format_tab_line(tab + 2,&format!("{} : {}::init_asn1(),", k,extract_type_name(v))));
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
		rets.push_str(&format_tab_line(tab + 1,"let mut _endsize :usize = code.len();"));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
		}

		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("retv += self.{}.decode_asn1(&code[retv.._endsize])?;",self.selname)));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, &format!("_outs = format!(\"decode {} retv [{{}}]\\n\",retv);",self.selname)));
			rets.push_str(&format_tab_line(tab + 1, "let _ = _outf.write(_outs.as_bytes())?;"));
		}
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("let k = self.{}.decode_select()?;", self.selname)));

		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, &format!("_outs = format!(\"select {{}}\\n\",k);")));
			rets.push_str(&format_tab_line(tab + 1, "let _ = _outf.write(_outs.as_bytes())?;"));
		}
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
				rets.push_str(&format_tab_line(tab + 2,&format!("retv += self.{}.decode_asn1(&code[retv.._endsize])?;", self.parsenames[idx])));
				if self.debugenable {
					rets.push_str(&format_tab_line(tab + 2, &format!("_outs = format!(\"decode {} retv [{{}}]\\n\",retv);",self.parsenames[idx])));
					rets.push_str(&format_tab_line(tab + 2, "let _ = _outf.write(_outs.as_bytes())?;"));
				}
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
		rets.push_str(&format_tab_line(tab + 1,"let mut _encv : Vec<u8>;"));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
		}
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("_encv = self.{}.encode_asn1()?;", self.selname)));
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
				if self.debugenable {
					rets.push_str(&format_tab_line(tab + 2, &(format!("_outs = format!(\"format {} output {{:?}}\\n\",vk);", self.parsenames[idx]))));
					rets.push_str(&format_tab_line(tab + 2, "let _ = _outf.write(_outs.as_bytes())?;"));
				}
				rets.push_str(&format_tab_line(tab + 2, "for i in 0..vk.len() {"));
				rets.push_str(&format_tab_line(tab + 3, "_encv.push(vk[i]);"));
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

		rets.push_str(&format_tab_line(tab + 1, "retv = Vec::new();"));

		rets.push_str(&format_tab_line(tab + 1, "for i in 0.._encv.len() {"));
		rets.push_str(&format_tab_line(tab + 2, "retv.push(_encv[i]);"));
		rets.push_str(&format_tab_line(tab + 1, "}"));

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
		rets.push_str(&format_tab_line(tab + 1,"let _outs :String;"));
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("_outs = asn1_format_line(tab,&format!(\"{{}} ASN1_CHOICE {}\",name));",self.sname)));
		rets.push_str(&format_tab_line(tab + 1,"let _ = iowriter.write(_outs.as_bytes())?;"));
		rets.push_str(&format_tab_line(tab + 1,""));
		rets.push_str(&format_tab_line(tab + 1,&format!("let selname = format!(\"{}\");",self.selname)));
		rets.push_str(&format_tab_line(tab + 1,&format!("let _ = self.{}.print_asn1(&selname,tab + 1, iowriter)?;",self.selname)));
		rets.push_str(&format_tab_line(tab + 1,""));
		sidx = 0;
		idx = 0;
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				if sidx == 0 {
					rets.push_str(&format_tab_line(tab + 1,&format!("if k == \"{}\" {{", self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab + 1,&format!("}} else if k == \"{}\" {{", self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2, &format!("let nname = format!(\"{}\");", self.parsenames[idx])));
				rets.push_str(&format_tab_line(tab + 2, &format!("let _ = self.{}.print_asn1(&nname,tab+1, iowriter)?;",self.parsenames[idx])));

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
			self.errname.push_str(&get_random_bytes(20));
			//asn1_gen_log_trace!("errname [{}]",self.errname);

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

		//asn1_gen_log_trace!("code\n{}",rets);

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
				//asn1_gen_log_trace!("token [{}]",c);
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
				//asn1_gen_log_trace!("=");
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
				k = "".to_string();
				v = "".to_string();
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

#[allow(dead_code)]
struct TypeChoiceSyn {
	seltypename :String,
	valarr :Vec<String>,
	valmaps :HashMap<String,String>,
	typmaps :HashMap<String,i32>,
	sname :String,
	debugenable :i32,
}

impl TypeChoiceSyn {
	pub fn new() -> TypeChoiceSyn {
		TypeChoiceSyn {
			seltypename : "".to_string(),
			valarr : Vec::new(),
			valmaps : HashMap::new(),
			typmaps : HashMap::new(),
			sname : "".to_string(),
			debugenable : 0,
		}
	}

	pub fn set_struct_name(&mut self,s :&str) {
		self.sname = format!("{}",s);
		return;
	}

	pub fn set_name(&mut self, k :&str,v :&str) {
		self.valarr.push(format!("{}",k));
		self.valmaps.insert(format!("{}",k),format!("{}",v));
		return;
	}

	pub fn set_attr_name(&mut self, _k :&str, _v :&str) -> Result<(),Box<dyn Error>> {
		return Ok(());
	}

	pub fn format_asn1_code(&self) -> Result<String,Box<dyn Error>> {
		return Ok("".to_string());
	}
}


impl syn::parse::Parse for TypeChoiceSyn {
	fn parse(input :syn::parse::ParseStream) -> syn::parse::Result<Self> {
		let mut retv = TypeChoiceSyn::new();
		let mut k :String = "".to_string();
		let mut v :String = "".to_string();
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
			} else if input.peek(syn::Token![=]) {
				let _c : syn::token::Eq = input.parse()?;
				//asn1_gen_log_trace!("=");
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
				k = "".to_string();
				v = "".to_string();
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
pub fn asn1_type_choice(_attr :TokenStream, item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let co :syn::DeriveInput;
	let nargs = _attr.clone();
	let sname :String;
	let mut cs :TypeChoiceSyn = syn::parse_macro_input!(nargs as TypeChoiceSyn);

	match syn::parse::<syn::DeriveInput>(item.clone()) {
		Ok(v) => {
			co = v.clone();
		},
		Err(_e) => {
			asn1_syn_error_fmt!("not parse \n{}",item.to_string());
		}
	}

	sname = format!("{}",co.ident);
	//asn1_gen_log_trace!("sname [{}]",sname);
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
    cc.push_str("\n");
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}

#[proc_macro_attribute]
pub fn asn1_choice(_attr :TokenStream,item :TokenStream) -> TokenStream {
	//asn1_gen_log_trace!("item\n{}",item.to_string());
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
	//asn1_gen_log_trace!("sname [{}]",sname);
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
    cc.push_str("\n");
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}

asn1_gen_error_class!{SequenceSynError}

struct SequenceSyn {
	debugenable : bool,
	sname :String,
	errname :String,
	parsenames :Vec<String>,
	kmap :HashMap<String,String>,
}

impl SequenceSyn {
	pub fn new() -> Self {
		SequenceSyn{
			debugenable : false,
			sname : "".to_string(),
			errname : "".to_string(),
			parsenames : Vec::new(),
			kmap : HashMap::new(),
		}
	}

	pub fn set_struct_name(&mut self, n :&str) {
		self.sname = format!("{}",n);
		return;
	}

	pub fn set_attr(&mut self, k :&str, v :&str) -> Result<(),Box<dyn Error>> {
		if k == "debug" && (v == "enable" || v == "disable") {
			if v == "enable" {
				self.debugenable = true;
			} else {
				self.debugenable = false;
			}
		} else {
			asn1_gen_new_error!{SequenceSynError,"can not accept k[{}] v [{}]",k,v}
		}
		Ok(())
	}

	pub fn set_name(&mut self, k :&str,n :&str) {
		if k == "error" {
			self.errname = format!("{}",n);
		} else {
			self.parsenames.push(format!("{}",k));
			self.kmap.insert(format!("{}",k),format!("{}",n));
		}
		return;
	}

	fn format_init_asn1(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn init_asn1() -> Self {"));
		rets.push_str(&format_tab_line(tab + 1, &format!("{} {{",self.sname)));
		for k in self.parsenames.iter() {
			let v = self.kmap.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2, &format!("{} : {}::init_asn1(),", k,extract_type_name(v))));
		}
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_decode_asn1(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let mut retv :usize = 0;"));
		rets.push_str(&format_tab_line(tab + 1, "let mut _endsize :usize = code.len();"));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _lastv :usize = 0;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _i :usize;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _lasti :usize;"));
		}
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "_lastv = retv;"));
		}
		for k in self.parsenames.iter() {			
			rets.push_str(&format_tab_line(tab + 1, ""));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1, &format!("_outs = format!(\"decode {}.{} will decode at {{}}\\n\",retv);",self.sname,k)));
				rets.push_str(&format_tab_line(tab + 1, "let _ = _outf.write(_outs.as_bytes())?;"));
			}
			rets.push_str(&format_tab_line(tab + 1, &format!("let ro = self.{}.decode_asn1(&code[retv.._endsize]);",k)));
			rets.push_str(&format_tab_line(tab + 1, "if ro.is_err() {"));
			rets.push_str(&format_tab_line(tab + 2, &format!("let e = ro.err().unwrap();")));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 2, &format!("_outs = format!(\"decode {}.{} error {{:?}}\",e);",self.sname,k)));
				rets.push_str(&format_tab_line(tab + 2,"let _ = _outf.write(_outs.as_bytes())?;"));
			}
			rets.push_str(&format_tab_line(tab + 2, "return Err(e);"));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1, &format!("_lastv = retv;")));	
			}
			rets.push_str(&format_tab_line(tab + 1, &format!("retv += ro.unwrap();")));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1,&format!("_outs = format!(\"decode {}.{} retv {{}} _lastv {{}}\",retv,_lastv);",self.sname,k)));
				rets.push_str(&format_tab_line(tab + 1,"_i = 0;"));
				rets.push_str(&format_tab_line(tab + 1,"_lasti = 0;"));
				rets.push_str(&format_tab_line(tab + 1,"while _i < (retv - _lastv) {"));
				rets.push_str(&format_tab_line(tab + 2,"if (_i % 16) == 0 {"));
				rets.push_str(&format_tab_line(tab + 3,"if _i > 0 {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\"    \");"));
				rets.push_str(&format_tab_line(tab + 4,"while _lasti != _i {"));
				rets.push_str(&format_tab_line(tab + 5,"if code[(_lastv + _lasti)] >= 0x20 && code[(_lastv + _lasti)] <= 0x7e {"));
				rets.push_str(&format_tab_line(tab + 6,"_outs.push(code[(_lastv+_lasti)] as char);"));
				rets.push_str(&format_tab_line(tab + 5,"} else {"));
				rets.push_str(&format_tab_line(tab + 6,"_outs.push_str(\".\");"));
				rets.push_str(&format_tab_line(tab + 5,"}"));
				rets.push_str(&format_tab_line(tab + 5,"_lasti += 1;"));
				rets.push_str(&format_tab_line(tab + 4,"}"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"_outs.push_str(&format!(\"\\n0x{:08x}:\",_i));"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 2,"_outs.push_str(&format!(\" 0x{:02x}\", code[_lastv + _i]));"));
				rets.push_str(&format_tab_line(tab + 2,"_i += 1;"));
				rets.push_str(&format_tab_line(tab + 1,"}"));
				rets.push_str(&format_tab_line(tab + 1,"if _lasti != _i {"));
				rets.push_str(&format_tab_line(tab + 2,"while (_i % 16) != 0 {"));
				rets.push_str(&format_tab_line(tab + 3,"_outs.push_str(\"     \");"));
				rets.push_str(&format_tab_line(tab + 3,"_i += 1;"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 2,"_outs.push_str(\"    \");"));
				rets.push_str(&format_tab_line(tab + 2,"while _lasti < (retv - _lastv) {"));
				rets.push_str(&format_tab_line(tab + 3,"if code[(_lastv + _lasti)] >= 0x20 && code[(_lastv + _lasti)] <= 0x7e {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push(code[(_lastv+_lasti)] as char);"));
				rets.push_str(&format_tab_line(tab + 3,"} else {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\".\");"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"_lasti += 1;"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 1,"}"));
				rets.push_str(&format_tab_line(tab + 1,"_outs.push_str(\"\\n\");"));
				rets.push_str(&format_tab_line(tab + 1,"let _ = _outf.write(_outs.as_bytes())?;"));
			}
		}


		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, &format!("_outs = format!(\"{} total {{}}\\n\",retv);", self.sname)));
			rets.push_str(&format_tab_line(tab + 1, "let _ = _outf.write(_outs.as_bytes())?;"));
		}

		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab + 1, "Ok(retv)"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;		
	}

	fn format_encode_asn1(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let mut _v8 :Vec<u8> = Vec::new();"));
		if self.debugenable {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
		}
		if self.parsenames.len() > 1 {
			rets.push_str(&format_tab_line(tab + 1, "let mut encv :Vec<u8>;"));	
		} else {
			rets.push_str(&format_tab_line(tab + 1, "let encv :Vec<u8>;"));
		}


		
		for k in self.parsenames.iter() {
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, &format!("encv = self.{}.encode_asn1()?;",k)));
			rets.push_str(&format_tab_line(tab + 1, "for i in 0..encv.len() {"));
			rets.push_str(&format_tab_line(tab + 2, "_v8.push(encv[i]);"));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			if self.debugenable {
				rets.push_str(&format_tab_line(tab + 1,""));
				rets.push_str(&format_tab_line(tab + 1,&format!("_outs = format!(\"format {}.{} {{:?}}\\n\",encv);", self.sname, k)));
				rets.push_str(&format_tab_line(tab + 1,"_outf.write(_outs.as_bytes())?;"));
			}
		}


		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab + 1, "Ok(_v8)"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_print_asn1(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {"));
		if self.parsenames.len() == 0 {
			rets.push_str(&format_tab_line(tab + 1, "let s :String;"));
		} else {
			rets.push_str(&format_tab_line(tab + 1, "let mut s :String;"));
		}
		rets.push_str(&format_tab_line(tab + 1, &format!("s = asn1_format_line(tab,&format!(\"{{}} {}\", name));", self.sname)));
		rets.push_str(&format_tab_line(tab + 1, "iowriter.write(s.as_bytes())?;"));
		
		rets.push_str(&format_tab_line(tab + 1, ""));
		for k in self.parsenames.iter() {
			rets.push_str(&format_tab_line(tab + 1, &format!("s = format!(\"{}\");", k)));
			rets.push_str(&format_tab_line(tab + 1, &format!("self.{}.print_asn1(&s,tab + 1, iowriter)?;",k)));
			rets.push_str(&format_tab_line(tab + 1, ""));
		}

		rets.push_str(&format_tab_line(tab + 1, "Ok(())"));
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	pub fn format_asn1_code(&mut self) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		if self.sname.len() == 0 {
			asn1_gen_new_error!{SequenceSynError,"need sname "}
		}

		if self.errname.len() == 0 {
			self.errname = format!("{}Error",self.sname);
			self.errname.push_str(&get_random_bytes(20));
			rets.push_str(&format_tab_line(0,&format!("asn1obj_error_class!{{{}}}", self.errname)));
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
		//asn1_gen_log_trace!("code\n{}",rets);
		Ok(rets)
	}
}

impl syn::parse::Parse for SequenceSyn {
	fn parse(input :syn::parse::ParseStream) -> syn::parse::Result<Self> {
		let mut retv = SequenceSyn::new();
		let mut k :String = "".to_string();
		let mut v :String = "".to_string();
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
			} else if input.peek(syn::Token![=]) {
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
			} else {
				if input.is_empty() {
					if k.len() != 0 && v.len() != 0 {
						let ov = retv.set_attr(&k,&v);
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
pub fn asn1_sequence(_attr :TokenStream,item :TokenStream) -> TokenStream {
	//asn1_gen_log_trace!("item\n{}\n_attr\n{}",item.to_string(),_attr.to_string());
	let co :syn::DeriveInput;
	let nargs = _attr.clone();
	let sname :String;
	let mut cs :SequenceSyn = syn::parse_macro_input!(nargs as SequenceSyn);

	match syn::parse::<syn::DeriveInput>(item.clone()) {
		Ok(v) => {
			co = v.clone();
		},
		Err(_e) => {
			asn1_syn_error_fmt!("not parse \n{}",item.to_string());
		}
	}

	sname = format!("{}",co.ident);
	//asn1_gen_log_trace!("sname [{}]",sname);
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

	//asn1_gen_log_trace!(" ");

	/*now to compile ok*/
    //let cc = format_code(&sname,names.clone(),structnames.clone());
    let mut cc = item.to_string();
    cc.push_str("\n");
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}