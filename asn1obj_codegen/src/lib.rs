
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

#[macro_use]
mod errors;
#[macro_use]
mod logger;

use crate::logger::*;

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
		let dbgval : bool;
		if ASN1_GEN_PROC_VAR.debuglevel > 0 {
			dbgval = true;
		} else {
			dbgval = false;
		}
		ObjSelectorSyn {
			defname :"".to_string(),
			debugenable : dbgval,
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

	fn format_encode_json(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		if self.parsenames.len() == 1 {
			rets.push_str(&format_tab_line(tab + 1, &format!("return self.{}.encode_json(key,val);",self.parsenames[0])));
		} else if self.parsenames.len() > 1 {
			rets.push_str(&format_tab_line(tab + 1, "let mut mainv = serde_json::json!({});"));
			rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));

			rets.push_str(&format_tab_line(tab + 1, " "));
			for k in self.parsenames.iter() {
				rets.push_str(&format_tab_line(tab + 1, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",k,k)));
			}
			rets.push_str(&format_tab_line(tab + 1, " "));
			rets.push_str(&format_tab_line(tab + 1,"if key.len() > 0 {"));
			rets.push_str(&format_tab_line(tab + 2, "val[key] = mainv;"));
			rets.push_str(&format_tab_line(tab + 1,"} else {"));
			rets.push_str(&format_tab_line(tab + 2, "*val = mainv;"));
			rets.push_str(&format_tab_line(tab + 1,"}"));
			rets.push_str(&format_tab_line(tab + 1, " "));
			rets.push_str(&format_tab_line(tab + 1,"Ok(idx)"));
		}
		/*now to */
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_decode_json(&self, tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab , "fn decode_json(&mut self, key :&str,val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		if self.parsenames.len() == 1 {
			rets.push_str(&format_tab_line(tab + 1, &format!("return self.{}.decode_json(key,val);",self.parsenames[0])));
		} else if self.parsenames.len() > 1 {
			rets.push_str(&format_tab_line(tab + 1, "let mainv : serde_json::value::Value;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));
			rets.push_str(&format_tab_line(tab + 1, " "));
			rets.push_str(&format_tab_line(tab + 1, "if key.len() > 0 {"));
			rets.push_str(&format_tab_line(tab + 2, "let k = val.get(key);"));
			rets.push_str(&format_tab_line(tab + 2, "if k.is_none() {"));
			for k in self.parsenames.iter() {
				let v = self.parsemap.get(k).unwrap();
				rets.push_str(&format_tab_line(tab + 3, &format!("self.{} = {}::init_asn1();", k,extract_type_name(v))));
			}
			rets.push_str(&format_tab_line(tab + 3, "return Ok(0);"));
			rets.push_str(&format_tab_line(tab + 2, "}"));
			rets.push_str(&format_tab_line(tab + 2, "mainv = serde_json::json!(k.clone());"));
			rets.push_str(&format_tab_line(tab + 1, "} else {"));
			rets.push_str(&format_tab_line(tab + 2, "mainv = val.clone();"));
			rets.push_str(&format_tab_line(tab + 1, "}"));

			rets.push_str(&format_tab_line(tab + 1, " "));
			rets.push_str(&format_tab_line(tab + 1,"if !mainv.is_object() {"));
			rets.push_str(&format_tab_line(tab + 2,&format!("asn1obj_new_error!{{{},\"[{{}}] not valid object\",key}}",self.errname)));
			rets.push_str(&format_tab_line(tab + 1,"}"));

			rets.push_str(&format_tab_line(tab + 1, " "));
			for k in self.parsenames.iter() {
				rets.push_str(&format_tab_line(tab + 1,&format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",k,k)));
			}
			rets.push_str(&format_tab_line(tab + 1, " "));
			rets.push_str(&format_tab_line(tab + 1, "return Ok(idx);"));
		}
		/*now to */
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
		rets.push_str(&(self.format_encode_json(1)));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&(self.format_decode_json(1)));
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

///  macro for asn1_choice
///  please see the example of asn1_choice
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
		let dbgval : bool;
		if ASN1_GEN_PROC_VAR.debuglevel > 0 {
			dbgval = true;
		} else {
			dbgval = false;
		}
		ChoiceSyn{
			debugenable : dbgval,
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

	fn format_encode_json(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut idx :usize;
		let mut sidx :usize;
		rets.push_str(&format_tab_line(tab,"fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>>{"));
		rets.push_str(&format_tab_line(tab + 1, "let mut mainv :serde_json::value::Value = serde_json::json!({});"));
		rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));
		rets.push_str(&format_tab_line(tab + 1, " "));
		rets.push_str(&format_tab_line(tab + 1, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",self.selname,self.selname)));
		rets.push_str(&format_tab_line(tab + 1, &format!("let c :String = self.{}.encode_select()?;",self.selname)));
		idx = 0;
		sidx = 0;
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				if sidx > 0 {
					rets.push_str(&format_tab_line(tab+1,&format!("}} else if c == \"{}\" {{",self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab+1,&format!("if c == \"{}\" {{",self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2,&format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",self.parsenames[idx],self.parsenames[idx])));
				sidx += 1;
			}
			idx += 1;
		}
		if sidx > 0 {
			rets.push_str(&format_tab_line(tab +1 ,"} else {"));
			rets.push_str(&format_tab_line(tab + 2,&format!("asn1obj_new_error!{{{},\"not support [{{}}]\",c}}",self.errname)));
			rets.push_str(&format_tab_line(tab +1 ,"}"));
		} else{
			rets.push_str(&format_tab_line(tab + 1,&format!("asn1obj_new_error!{{{},\"not support [{{}}]\",c}}",self.errname)));
		}

		rets.push_str(&format_tab_line(tab + 1," "));
		rets.push_str(&format_tab_line(tab + 1,"if key.len() > 0 {"));
		rets.push_str(&format_tab_line(tab + 2,"val[key] = mainv;"));
		rets.push_str(&format_tab_line(tab + 1,"} else {"));
		rets.push_str(&format_tab_line(tab + 2,"*val = mainv;"));
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab + 1," "));
		rets.push_str(&format_tab_line(tab + 1,"return Ok(idx);"));

		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_decode_json(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut idx :usize;
		let mut sidx :usize;
		rets.push_str(&format_tab_line(tab,"fn decode_json(&mut self, key :&str,val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>>{"));
		rets.push_str(&format_tab_line(tab + 1,"let mainv :serde_json::value::Value;"));
		rets.push_str(&format_tab_line(tab + 1,"let mut idx :i32=0;"));
		rets.push_str(&format_tab_line(tab + 1,"if key.len() > 0 {"));
		rets.push_str(&format_tab_line(tab + 2,"let k = val.get(key);"));
		rets.push_str(&format_tab_line(tab + 2,"if k.is_none() {"));
		for k in self.parsenames.iter() {
			let v = self.typemap.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 3,&format!("self.{} = {}::init_asn1();", k,extract_type_name(v))));
		}
		rets.push_str(&format_tab_line(tab + 2,"return Ok(0);"));
		rets.push_str(&format_tab_line(tab + 2,"}"));
		rets.push_str(&format_tab_line(tab + 2,"mainv = serde_json::json!(k.clone());"));
		rets.push_str(&format_tab_line(tab + 1,"} else {"));
		rets.push_str(&format_tab_line(tab + 2,"mainv = val.clone();"));
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab + 1," "));
		rets.push_str(&format_tab_line(tab + 1,"if !mainv.is_object() {"));
		rets.push_str(&format_tab_line(tab + 2,&format!("asn1obj_new_error!{{{},\"not object to decode\"}}",self.errname)));
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab + 1," "));
		rets.push_str(&format_tab_line(tab + 1,&format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",self.selname,self.selname)));
		idx = 0;
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				let k = &self.parsenames[idx];
				let v = self.typemap.get(k).unwrap();
				rets.push_str(&format_tab_line(tab + 1,&format!("self.{} = {}::init_asn1();", k,extract_type_name(v))));
			}
			idx += 1;
		}
		rets.push_str(&format_tab_line(tab + 1," "));
		rets.push_str(&format_tab_line(tab + 1,&format!("let c :String = self.{}.decode_select()?;",self.selname)));
		idx = 0;
		sidx = 0;
		while idx < self.parsenames.len() {
			if self.parsenames[idx] != self.selname {
				if sidx > 0 {
					rets.push_str(&format_tab_line(tab + 1,&format!("}} else if c == \"{}\" {{", self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab + 1,&format!("if c == \"{}\" {{", self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2,&format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",self.parsenames[idx],self.parsenames[idx])));
				sidx += 1;
			}
			idx += 1;
		}

		if sidx > 0 {
			rets.push_str(&format_tab_line(tab +1 ,"} else {"));
			rets.push_str(&format_tab_line(tab + 2,&format!("asn1obj_new_error!{{{},\"not support [{{}}]\",c}}",self.errname)));
			rets.push_str(&format_tab_line(tab +1 ,"}"));
		} else{
			rets.push_str(&format_tab_line(tab + 1,&format!("asn1obj_new_error!{{{},\"not support [{{}}]\",c}}",self.errname)));
		}

		rets.push_str(&format_tab_line(tab + 1," "));
		rets.push_str(&format_tab_line(tab + 1,"return Ok(idx);"));
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
		rets.push_str(&self.format_encode_json(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_decode_json(1));
		rets.push_str(&format_tab_line(1,""));
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
struct IntChoiceSyn {
	seltypename :String,
	valarr :Vec<String>,
	errname :String,
	valmaps :HashMap<String,String>,
	typmaps :HashMap<String,i32>,
	sname :String,
	debugenable :i32,
}

impl IntChoiceSyn {
	pub fn new() -> IntChoiceSyn {
		IntChoiceSyn {
			seltypename : "".to_string(),
			valarr : Vec::new(),
			valmaps : HashMap::new(),
			typmaps : HashMap::new(),
			sname : "".to_string(),
			errname : "".to_string(),
			debugenable : ASN1_GEN_PROC_VAR.debuglevel,
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

	fn parse_value(&self, s :&str) -> Result<i64,Box<dyn Error>> {
		match i64::from_str_radix(s,10) {
			Ok(v) => {              
				return Ok(v);
			},
			Err(e) => {
				asn1_gen_new_error!{ChoiceSynError,"parse [{}] error[{:?}]",s,e}
			}
		}
	}

	pub fn set_attr_name(&mut self, _k :&str, _v :&str) -> Result<(),Box<dyn Error>> {
		let iv :i64;
		if _k.eq("debug") {
			iv = self.parse_value(_v)?;
			self.debugenable = iv as i32;
		} else if _k.eq("selector") {
			self.seltypename = format!("{}",_v);
		} else if _k.eq("error") {
			self.errname = format!("{}",_v);
		}else {
			iv = self.parse_value(_v)?;
			self.typmaps.insert(format!("{}",_k), iv as i32);
		}
		return Ok(());
	}

	fn check_variables(&self) -> Result<(),Box<dyn Error>> {
		/*first to check for the typmaps are in var*/
		let mut found :bool;
		for (k,_) in self.typmaps.iter() {
			found = false;
			for (k2,_)	 in self.valmaps.iter() {
				if k.eq(k2) {
					found = true;
					break;
				}
			}


			if !found {
				asn1_gen_new_error!{ChoiceSynError,"{} not found in valmaps", k}
			}
		}

		/*now to check seltype in */
		found = false;
		for (k, _) in self.valmaps.iter() {
			if k.eq(&self.seltypename) {
				found = true;
				break;
			}
		}

		if !found {
			asn1_gen_new_error!{ChoiceSynError,"{} not found in valmaps ", self.seltypename}
		}

		for (k,_) in self.valmaps.iter() {
			found = false;
			for (k2,_)	 in self.typmaps.iter() {
				if k.eq(k2) {
					found = true;
					break;
				}
			}

			if !found {
				if k.eq(&self.seltypename) {
					found = true;
				}
			}


			if !found {
				asn1_gen_new_error!{ChoiceSynError,"{} not found in typmaps or seltypename", k}
			}

		}

		Ok(())
	}

	fn format_init_asn1(&self, tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab, "fn init_asn1() -> Self {"));
		rets.push_str(&format_tab_line(tab + 1, &format!("{} {{", self.sname)));

		for c in self.valarr.iter() {
			if c.eq(&self.seltypename) {
				rets.push_str(&format_tab_line(tab + 2,&format!("{} : -1,", self.seltypename)));
			} else {
				match self.valmaps.get(c) {
					Some(v) => {
						rets.push_str(&format_tab_line(tab + 2,&format!("{} : {}::init_asn1(),", c,extract_type_name(v))));
					},
					None => {
						asn1_gen_new_error!{ChoiceSynError,"can not get [{}] variable", c}
					}
				}
			}
		}

		rets.push_str(&format_tab_line(tab + 1, "}"));
		rets.push_str(&format_tab_line(tab, "}"));
		Ok(rets)
	}

	fn format_decode_asn1(&self, tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab, "fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab+1, "let mut ores : Result<usize,Box<dyn Error>>;"));
		if self.debugenable > 0 {
			rets.push_str(&format_tab_line(tab + 1, "let mut _outf = std::io::stderr();"));
			rets.push_str(&format_tab_line(tab + 1, "let mut _outs :String;"));
		}
		rets.push_str(&format_tab_line(tab+1, " "));
		for (k,v) in self.typmaps.iter() {
			if self.debugenable > 0 {
				rets.push_str(&(format_tab_line(tab+1,&(format!("_outs = format!(\"will decode {}\\n\");",k)))));
				rets.push_str(&(format_tab_line(tab+1,&(format!("_outf.write(_outs.as_bytes())?;")))));
			}
			rets.push_str(&format_tab_line(tab+1, &format!("ores = self.{}.decode_asn1(code);",k)));
			rets.push_str(&format_tab_line(tab+1,"if ores.is_ok() {"));
			rets.push_str(&format_tab_line(tab+2,&format!("self.{} = {};",self.seltypename,v)));
			rets.push_str(&format_tab_line(tab+2,"return Ok(ores.unwrap());"));

			rets.push_str(&format_tab_line(tab + 1, "}"));
			rets.push_str(&format_tab_line(tab+1," "));
		}

		rets.push_str(&format_tab_line(tab + 1,&format!("asn1obj_new_error!{{{},\"not supported type\"}}",self.errname)));
		rets.push_str(&format_tab_line(tab, "}"));
		Ok(rets)
	}

	fn format_encode_asn1(&self, tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		let mut idx :i32 = 0;
		rets.push_str(&format_tab_line(tab,"fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let retv :Vec<u8>;"));
		rets.push_str(&format_tab_line(tab + 1, " "));
		for (k,v) in self.typmaps.iter() {
			if idx == 0 {
				rets.push_str(&format_tab_line(tab + 1, &format!("if self.{} == {} {{", self.seltypename,v)));	
			} else {
				rets.push_str(&format_tab_line(tab + 1, &format!("}} else if self.{} == {} {{", self.seltypename,v)));	
			}			
			rets.push_str(&format_tab_line(tab + 2,&format!("retv = self.{}.encode_asn1()?;", k)));
			idx += 1;
		}
		if idx == 0 {
			asn1_gen_new_error!{ChoiceSynError,"no type insert"}
		}
		rets.push_str(&format_tab_line(tab + 1 ,"} else {"));
		rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{{},\"not supported type {{}}\", self.{}}}",self.errname,self.seltypename)));
		rets.push_str(&format_tab_line(tab+1,"}"));
		rets.push_str(&format_tab_line(tab+1," "));
		rets.push_str(&format_tab_line(tab+1,"Ok(retv)"));
		rets.push_str(&format_tab_line(tab,"}"));
		Ok(rets)
	}

	fn format_print_asn1(&self, tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		let mut idx :i32 = 0;
		rets.push_str(&format_tab_line(tab,"fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab+1,&format!("let  s :String;")));
		rets.push_str(&format_tab_line(tab+1,&format!(" ")));
		rets.push_str(&format_tab_line(tab+1,&format!("s = asn1_format_line(tab,&format!(\"{{}}.{} type {{}}\",name,self.{}));",self.seltypename,self.seltypename)));
		rets.push_str(&format_tab_line(tab+1,"iowriter.write(s.as_bytes())?;"));
		rets.push_str(&format_tab_line(tab+1," "));
		for (k,v) in self.typmaps.iter() {
			if idx == 0 {
				rets.push_str(&format_tab_line(tab+1,&format!("if self.{} == {} {{", self.seltypename,v)));
			} else {
				rets.push_str(&format_tab_line(tab+1,&format!("}} else if self.{} == {} {{", self.seltypename,v)));
			}
			rets.push_str(&format_tab_line(tab+2,&format!("self.{}.print_asn1(\"{}\",tab+1,iowriter)?;",k,k)));
			idx += 1;
		}
		if idx == 0 {
			asn1_gen_new_error!{ChoiceSynError,"no type insert"}
		}
		rets.push_str(&format_tab_line(tab + 1 ,"} else {"));
		rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{{},\"not supported type {{}}\", self.{}}}",self.errname,self.seltypename)));
		rets.push_str(&format_tab_line(tab+1,"}"));
		rets.push_str(&format_tab_line(tab+1," "));
		rets.push_str(&format_tab_line(tab+1,"Ok(())"));
		rets.push_str(&format_tab_line(tab,"}"));
		Ok(rets)
	}

	fn format_error_code(&mut self,tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		if self.errname.len() == 0 {
			self.errname = format!("{}{}Error", self.sname,get_random_bytes(16));
			rets.push_str(&format_tab_line(tab,&format!("asn1obj_error_class!{{{}}}",self.errname)));
			rets.push_str(&format_tab_line(tab," "));
		}
		return Ok(rets);
	}

	fn format_encode_json(&self,tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		let mut idx :usize;
		rets.push_str(&format_tab_line(tab,"fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let mut mainv :serde_json::value::Value = serde_json::json!({});"));
		rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));
		rets.push_str(&format_tab_line(tab + 1, "let mut cint :Asn1Integer = Asn1Integer::init_asn1();"));
		rets.push_str(&format_tab_line(tab + 1, " "));
		rets.push_str(&format_tab_line(tab + 1, &format!("cint.val = self.{} as i64;",self.seltypename)));
		rets.push_str(&format_tab_line(tab + 1, &format!("idx += cint.encode_json(\"{}\",&mut mainv)?;",self.seltypename)));
		rets.push_str(&format_tab_line(tab + 1, " "));
		idx = 0;
		for (k,v) in self.typmaps.iter() { 
			if idx > 0 {
				rets.push_str(&format_tab_line(tab + 1,&format!("}} else if self.{} == {} {{",self.seltypename,v)));
			} else {
				rets.push_str(&format_tab_line(tab + 1,&format!("if self.{} == {} {{",self.seltypename,v)));
			}
			rets.push_str(&format_tab_line(tab + 2, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",k,k)));	
			idx += 1;
		}
		if idx > 0 {
			rets.push_str(&format_tab_line(tab + 1, &format!("}} else {{")));
			rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{{},\"not support {{}} value\",self.{}}}",self.errname,self.seltypename)));
			rets.push_str(&format_tab_line(tab + 1, &format!("}}")));	
		} else {
			rets.push_str(&format_tab_line(tab + 1, &format!("asn1obj_new_error!{{{},\"not support {{}} value\",self.{}}}",self.errname,self.seltypename)));
		}
		rets.push_str(&format_tab_line(tab + 1, " "));
		rets.push_str(&format_tab_line(tab + 1, "if key.len() > 0 {"));
		rets.push_str(&format_tab_line(tab + 2, "val[key] = mainv;"));
		rets.push_str(&format_tab_line(tab + 1, "} else {"));
		rets.push_str(&format_tab_line(tab + 2, "*val = mainv;"));
		rets.push_str(&format_tab_line(tab + 1, "}"));
		rets.push_str(&format_tab_line(tab + 1, " "));
		rets.push_str(&format_tab_line(tab + 1, "return Ok(idx);"));
		rets.push_str(&format_tab_line(tab,"}"));
		return Ok(rets);
	}

	fn format_decode_json(&self,tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		let mut idx :usize;
		rets.push_str(&format_tab_line(tab,"fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab+1,"let mainv :serde_json::value::Value;"));
		rets.push_str(&format_tab_line(tab+1,"let mut idx :i32=0;"));
		rets.push_str(&format_tab_line(tab+1,"let mut cint :Asn1Integer = Asn1Integer::init_asn1();"));
		rets.push_str(&format_tab_line(tab+1," "));
		rets.push_str(&format_tab_line(tab+1,"if key.len() > 0 {"));
		rets.push_str(&format_tab_line(tab+2,"let k = val.get(key);"));
		rets.push_str(&format_tab_line(tab+2,"if k.is_none() {"));
		for c in self.valarr.iter() {
			if c.eq(&self.seltypename) {
				rets.push_str(&format_tab_line(tab + 3,&format!("self.{} = -1;", self.seltypename)));
			} else {
				match self.valmaps.get(c) {
					Some(v) => {
						rets.push_str(&format_tab_line(tab + 3,&format!("self.{} = {}::init_asn1();", c,extract_type_name(v))));
					},
					None => {
						asn1_gen_new_error!{ChoiceSynError,"can not get [{}] variable", c}
					}
				}
			}
		}
		rets.push_str(&format_tab_line(tab+3,"return Ok(0);"));
		rets.push_str(&format_tab_line(tab+2,"}"));
		rets.push_str(&format_tab_line(tab+2,"mainv = serde_json::json!(k.clone());"));
		rets.push_str(&format_tab_line(tab+1,"} else {"));
		rets.push_str(&format_tab_line(tab+2,"mainv = val.clone();"));
		rets.push_str(&format_tab_line(tab+1,"}"));
		rets.push_str(&format_tab_line(tab+1," "));
		rets.push_str(&format_tab_line(tab+1,"if !mainv.is_object() {"));
		rets.push_str(&format_tab_line(tab+2,&format!("asn1obj_new_error!{{{},\"not object to decode\"}}",self.errname)));
		rets.push_str(&format_tab_line(tab+1,"}"));
		rets.push_str(&format_tab_line(tab+1," "));
		rets.push_str(&format_tab_line(tab+1,&format!("idx += cint.decode_json(\"{}\",&mainv)?;",self.seltypename)));
		rets.push_str(&format_tab_line(tab+1,&format!("self.{} = cint.val as i32;",self.seltypename)));
		rets.push_str(&format_tab_line(tab+1," "));
		idx = 0;
		for (k,v) in self.typmaps.iter() { 
			if idx > 0 {
				rets.push_str(&format_tab_line(tab + 1,&format!("}} else if self.{} == {} {{",self.seltypename,v)));
			} else {
				rets.push_str(&format_tab_line(tab + 1,&format!("if self.{} == {} {{",self.seltypename,v)));
			}
			rets.push_str(&format_tab_line(tab + 2, &format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",k,k)));	
			idx += 1;
		}
		if idx > 0 {
			rets.push_str(&format_tab_line(tab + 1, &format!("}} else {{")));
			rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{{},\"not support {{}} value decode\",self.{}}}",self.errname,self.seltypename)));
			rets.push_str(&format_tab_line(tab + 1, &format!("}}")));	
		} else {
			rets.push_str(&format_tab_line(tab + 1, &format!("asn1obj_new_error!{{{},\"not support {{}} value decode\",self.{}}}",self.errname,self.seltypename)));
		}

		rets.push_str(&format_tab_line(tab+1," "));
		rets.push_str(&format_tab_line(tab+1,"return Ok(idx);"));
		rets.push_str(&format_tab_line(tab,"}"));
		return Ok(rets);
	}


	pub fn format_asn1_code(&mut self) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		self.check_variables()?;
		let c  = self.format_error_code(0)?;
		rets.push_str(&c);		

		rets.push_str(&format_tab_line(0,&format!("impl Asn1Op for {} {{", self.sname)));

		let c = self.format_encode_json(1)?;
		rets.push_str(&c);
		rets.push_str(&format_tab_line(1,""));

		let c = self.format_decode_json(1)?;
		rets.push_str(&c);
		rets.push_str(&format_tab_line(1,""));

		let c = self.format_init_asn1(1)?;
		rets.push_str(&c);
		rets.push_str(&format_tab_line(1,""));
		let c = self.format_decode_asn1(1)?;
		rets.push_str(&c);
		rets.push_str(&format_tab_line(1,""));

		let c = self.format_encode_asn1(1)?;
		rets.push_str(&c);
		rets.push_str(&format_tab_line(1,""));

		let c = self.format_print_asn1(1)?;
		rets.push_str(&c);



		rets.push_str(&format_tab_line(0,"}"));
		return Ok(rets);
	}
}


impl syn::parse::Parse for IntChoiceSyn {
	fn parse(input :syn::parse::ParseStream) -> syn::parse::Result<Self> {
		let mut retv = IntChoiceSyn::new();
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
			} else if input.peek(syn::LitInt) {
				if k.len() == 0 || v.len() != 0 {
					let e = format!("only accept v for int");
					return Err(syn::Error::new(input.span(),&e));
				}
				let c :syn::LitInt = input.parse()?;
				v = format!("{}",c);
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


///  the macro to expand for stype set
///  exampl
///  ```rust
///  use asn1obj_codegen::{asn1_sequence,asn1_int_choice};
///  use asn1obj::{asn1obj_error_class,asn1obj_new_error};
///  use asn1obj::base::*;
///  use asn1obj::complex::*;
///  use asn1obj::asn1impl::{Asn1Op};
///  use asn1obj::strop::asn1_format_line;
///  
///  use std::error::Error;
///  use std::io::Write;
///  use serde_json;
///  
///  
///  #[derive(Clone)]
///  #[asn1_int_choice(unicode=0,ascii=1,selector=stype)]
///  pub struct SpcString {
///  	pub stype :i32,
///  	pub unicode : Asn1Imp<Asn1OctData,0>,
///  	pub ascii :Asn1Imp<Asn1OctData,1>,
///  }
///  
///  
///  #[derive(Clone)]
///  #[asn1_sequence()]
///  pub struct SpcSerializedObject {
///  	pub classid :Asn1OctData,
///  	pub serializeddata : Asn1OctData,
///  }
///  
///  #[derive(Clone)]
///  #[asn1_int_choice(selector=stype,url=0,moniker=1,file=2)]
///  pub struct SpcLink {
///  	pub stype :i32,
///  	pub url :Asn1ImpSet<Asn1OctData,0>,
///  	pub moniker :Asn1ImpSet<SpcSerializedObject,1>,
///  	pub file :Asn1ImpSet<SpcString,2>,
///  }
///  
///  fn format_vecs(buf :&[u8], tab :i32) -> String {
///  	let mut outs :String = "".to_string();
///  	let mut lasti : usize = 0;
///  	let mut ki :usize;
///  	for i in 0..buf.len() {
///  		if (i%16) == 0 {
///  			if i > 0 {
///  				outs.push_str("    ");
///  				while lasti != i {
///  					if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
///  						outs.push(buf[lasti] as char);
///  					} else {
///  						outs.push_str(".");
///  					}
///  					lasti += 1;
///  				}
///  				outs.push_str("\n");
///  			}
///  
///  			for _j in 0..tab {
///  				outs.push_str("    ");
///  			}
///  		}
///  		if (i % 16) == 0 {
///  			outs.push_str(&format!("{:02x}", buf[i]));	
///  		} else {
///  			outs.push_str(&format!(":{:02x}", buf[i]));	
///  		}
///  		
///  	}
///  
///  	if lasti != buf.len() {
///  		ki = buf.len();
///  		while (ki % 16) != 0 {
///  			outs.push_str("   ");
///  			ki += 1;
///  		}
///  		outs.push_str("    ");
///  		while lasti != buf.len() {
///  			if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
///  				outs.push(buf[lasti] as char);
///  			} else {
///  				outs.push_str(".");
///  			}
///  			lasti += 1;
///  		}
///  	}
///  	outs.push_str("\n");
///  	return outs;
///  }
///  
///  fn main() -> Result<(),Box<dyn Error>> {
///  	let mut sps :SpcString = SpcString::init_asn1();
///  	sps.stype = 0;
///  	sps.unicode.val.data = vec![0x1,0x2,0x3];
///  	let mut spl :SpcLink = SpcLink::init_asn1();
///  	spl.stype = 2;
///  	spl.file.val.push(sps.clone());
///  	let outd = spl.encode_asn1()?;
///  	let mut outf = std::io::stdout();
///  	let outs = format!("outdata\n{}",format_vecs(&outd,1));
///  	outf.write(outs.as_bytes())?;
///  	spl.print_asn1("SpcLink",0,&mut outf)?;
///  	let mut outspl :SpcLink = SpcLink::init_asn1();
///  	let _ = outspl.decode_asn1(&outd)?;
///  	outspl.print_asn1("Out SpcLink",0,&mut outf)?;
///  
///  	let mut sps :SpcString = SpcString::init_asn1();
///  	sps.stype = 1;
///  	sps.ascii.val.data = vec![0x1,0x2,0x3];
///  	let mut spl :SpcLink = SpcLink::init_asn1();
///  	spl.stype = 2;
///  	spl.file.val.push(sps.clone());
///  	let outd = spl.encode_asn1()?;
///  	let mut outf = std::io::stdout();
///  	let outs = format!("outdata\n{}",format_vecs(&outd,1));
///  	outf.write(outs.as_bytes())?;
///  	spl.print_asn1("SpcLink",0,&mut outf)?;
///  	let mut outspl :SpcLink = SpcLink::init_asn1();
///  	let _ = outspl.decode_asn1(&outd)?;
///  	outspl.print_asn1("Out SpcLink",0,&mut outf)?;
///  
///  
///  
///  	let mut sps :SpcSerializedObject = SpcSerializedObject::init_asn1();
///  	sps.classid.data = vec![0x1,0x2,0x3];
///  	sps.serializeddata.data = vec![0x4,0x5,0x6];
///  	let mut spl :SpcLink = SpcLink::init_asn1();
///  	spl.stype = 1;
///  	spl.moniker.val.push(sps.clone());
///  	let outd = spl.encode_asn1()?;
///  	let outs = format!("outdata\n{}",format_vecs(&outd,1));
///  	outf.write(outs.as_bytes())?;
///  	spl.print_asn1("SpcLink",0,&mut outf)?;
///  	let mut outspl :SpcLink = SpcLink::init_asn1();
///  	let _ = outspl.decode_asn1(&outd)?;
///  	outspl.print_asn1("Out SpcLink",0,&mut outf)?;
///  
///  
///  	let mut sps :Asn1OctData = Asn1OctData::init_asn1();
///  	sps.data = vec![0x33,0x44,0x55];
///  	let mut spl :SpcLink = SpcLink::init_asn1();
///  	spl.stype = 0;
///  	spl.url.val.push(sps.clone());
///  	let outd = spl.encode_asn1()?;
///  	let outs = format!("outdata\n{}",format_vecs(&outd,1));
///  	outf.write(outs.as_bytes())?;
///  	spl.print_asn1("SpcLink",0,&mut outf)?;
///  	let mut outspl :SpcLink = SpcLink::init_asn1();
///  	let _ = outspl.decode_asn1(&outd)?;
///  	outspl.print_asn1("Out SpcLink",0,&mut outf)?;
///  
///  
///  	Ok(())
///  }
///  
///  /*
///  output:
///  outdata
///      a2:05:80:03:01:02:03                               .......
///  SpcLink.stype type 2
///      file[0].stype type 0
///          unicode IMP
///          unicode: ASN1_OCT_DATA
///              01:02:03                                           ...
///  Out SpcLink.stype type 2
///      file[0].stype type 0
///          unicode IMP
///          unicode: ASN1_OCT_DATA
///              01:02:03                                           ...
///  outdata
///      a2:05:81:03:01:02:03                               .......
///  SpcLink.stype type 2
///      file[0].stype type 1
///          ascii IMP
///          ascii: ASN1_OCT_DATA
///              01:02:03                                           ...
///  Out SpcLink.stype type 2
///      file[0].stype type 1
///          ascii IMP
///          ascii: ASN1_OCT_DATA
///              01:02:03                                           ...
///  outdata
///      a1:0a:04:03:01:02:03:04:03:04:05:06                ............
///  SpcLink.stype type 1
///      moniker[0] SpcSerializedObject
///          classid: ASN1_OCT_DATA
///              01:02:03                                           ...
///          serializeddata: ASN1_OCT_DATA
///              04:05:06                                           ...
///  Out SpcLink.stype type 1
///      moniker[0] SpcSerializedObject
///          classid: ASN1_OCT_DATA
///              01:02:03                                           ...
///          serializeddata: ASN1_OCT_DATA
///              04:05:06                                           ...
///  outdata
///      a0:05:04:03:33:44:55                               ....3DU
///  SpcLink.stype type 0
///      url[0]: ASN1_OCT_DATA
///          33:44:55                                           3DU
///  Out SpcLink.stype type 0
///      url[0]: ASN1_OCT_DATA
///          33:44:55                                           3DU
///  */
///  ```
///  ```rust
///  #[derive(Clone)]
///  #[asn1_int_choice(unicode=0,ascii=1,selector=stype)]
///  pub struct SpcString {
///  	pub stype :i32,
///  	pub unicode : Asn1Imp<Asn1OctData,0>,
///  	pub ascii :Asn1Imp<Asn1OctData,1>,
///  }
///  
///  
///  #[derive(Clone)]
///  #[asn1_sequence()]
///  pub struct SpcSerializedObject {
///  	pub classid :Asn1OctData,
///  	pub serializeddata : Asn1OctData,
///  }
///  
///  #[derive(Clone)]
///  #[asn1_int_choice(selector=stype,url=0,moniker=1,file=2)]
///  pub struct SpcLink {
///  	pub stype :i32,
///  	pub url :Asn1ImpSet<Asn1OctData,0>,
///  	pub moniker :Asn1ImpSet<SpcSerializedObject,1>,
///  	pub file :Asn1ImpSet<SpcString,2>,
///  }
///  ```
///  internal transfer
///  ```rust
///  pub struct SpcString
///  {
///      pub stype : i32, 
///      pub unicode : Asn1Imp<Asn1OctData, 0>, 
///      pub ascii :  Asn1Imp<Asn1OctData, 1>,
///  }
///  
///  asn1obj_error_class!{SpcStringoBxglRxcBmbANpbzError}
///   
///  impl Asn1Op for SpcString {
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mut mainv :serde_json::value::Value = serde_json::json!({});
///          let mut idx :i32 = 0;
///          let mut cint :Asn1Integer = Asn1Integer::init_asn1();
///           
///          cint.val = self.stype as i64;
///          idx += cint.encode_json("stype",&mut mainv)?;
///           
///          if self.stype == 0 {
///              idx += self.unicode.encode_json("unicode",&mut mainv)?;
///          } else if self.stype == 1 {
///              idx += self.ascii.encode_json("ascii",&mut mainv)?;
///          } else {
///              asn1obj_new_error!{SpcStringoBxglRxcBmbANpbzError,"not support {} value",self.stype}
///          }
///           
///          if key.len() > 0 {
///              val[key] = mainv;
///          } else {
///              *val = mainv;
///          }
///           
///          return Ok(idx);
///      }
///      
///      fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mainv :serde_json::value::Value;
///          let mut idx :i32=0;
///          let mut cint :Asn1Integer = Asn1Integer::init_asn1();
///           
///          if key.len() > 0 {
///              let k = val.get(key);
///              if k.is_none() {
///                  self.stype = -1;
///                  self.unicode = Asn1Imp::init_asn1();
///                  self.ascii = Asn1Imp::init_asn1();
///                  return Ok(0);
///              }
///              mainv = serde_json::json!(k.clone());
///          } else {
///              mainv = val.clone();
///          }
///           
///          if !mainv.is_object() {
///              asn1obj_new_error!{SpcStringoBxglRxcBmbANpbzError,"not object to decode"}
///          }
///           
///          idx += cint.decode_json("stype",&mainv)?;
///          self.stype = cint.val as i32;
///           
///          if self.stype == 0 {
///              idx += self.unicode.decode_json("unicode",&mainv)?;
///          } else if self.stype == 1 {
///              idx += self.ascii.decode_json("ascii",&mainv)?;
///          } else {
///              asn1obj_new_error!{SpcStringoBxglRxcBmbANpbzError,"not support {} value decode",self.stype}
///          }
///           
///          return Ok(idx);
///      }
///      
///      fn init_asn1() -> Self {
///          SpcString {
///              stype : -1,
///              unicode : Asn1Imp::init_asn1(),
///              ascii : Asn1Imp::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut ores : Result<usize,Box<dyn Error>>;
///           
///          ores = self.unicode.decode_asn1(code);
///          if ores.is_ok() {
///              self.stype = 0;
///              return Ok(ores.unwrap());
///          }
///           
///          ores = self.ascii.decode_asn1(code);
///          if ores.is_ok() {
///              self.stype = 1;
///              return Ok(ores.unwrap());
///          }
///           
///          asn1obj_new_error!{SpcStringoBxglRxcBmbANpbzError,"not supported type"}
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let retv :Vec<u8>;
///           
///          if self.stype == 0 {
///              retv = self.unicode.encode_asn1()?;
///          } else if self.stype == 1 {
///              retv = self.ascii.encode_asn1()?;
///          } else {
///              asn1obj_new_error!{SpcStringoBxglRxcBmbANpbzError,"not supported type {}", self.stype}
///          }
///           
///          Ok(retv)
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          let  s :String;
///           
///          s = asn1_format_line(tab,&format!("{}.stype type {}",name,self.stype));
///          iowriter.write(s.as_bytes())?;
///           
///          if self.stype == 0 {
///              self.unicode.print_asn1("unicode",tab+1,iowriter)?;
///          } else if self.stype == 1 {
///              self.ascii.print_asn1("ascii",tab+1,iowriter)?;
///          } else {
///              asn1obj_new_error!{SpcStringoBxglRxcBmbANpbzError,"not supported type {}", self.stype}
///          }
///           
///          Ok(())
///      }
///  }
///  
///  pub struct SpcSerializedObject
///  { 
///  	pub classid : Asn1OctData, 
///  	pub serializeddata : Asn1OctData, 
///  }
///  asn1obj_error_class!{SpcSerializedObjectErrorVn7V9sV9PRMPpFhGypOd}
///  
///  impl Asn1Op for SpcSerializedObject {
///      
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mut mainv :serde_json::value::Value = serde_json::json!({});
///          let mut idx :i32 = 0;
///          
///          idx += self.classid.encode_json("classid",&mut mainv)?;
///          idx += self.serializeddata.encode_json("serializeddata",&mut mainv)?;
///          
///          if key.len() > 0 {
///              val[key] = mainv;
///          } else {
///              *val = mainv;
///          }
///          
///          return Ok(idx);
///      }
///      
///      fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mainv :serde_json::value::Value;
///          let mut idx :i32=0;
///          
///          if key.len() > 0 {
///              let k = val.get(key);
///              if k.is_none() {
///                  self.classid = Asn1OctData::init_asn1();
///                  self.serializeddata = Asn1OctData::init_asn1();
///                  return Ok(0);
///              }
///              mainv = serde_json::json!(k.clone());
///          } else {
///              mainv = val.clone();
///          }
///          
///          if !mainv.is_object() {
///              asn1obj_new_error!{SpcSerializedObjectErrorVn7V9sV9PRMPpFhGypOd,"not object to decode"}
///          }
///          
///          idx += self.classid.decode_json("classid",&mainv)?;
///          idx += self.serializeddata.decode_json("serializeddata",&mainv)?;
///          
///          return Ok(idx);
///      }
///      
///      fn init_asn1() -> Self {
///          SpcSerializedObject {
///              classid : Asn1OctData::init_asn1(),
///              serializeddata : Asn1OctData::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut retv :usize = 0;
///          let mut _endsize :usize = code.len();
///          
///          let ro = self.classid.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          let ro = self.serializeddata.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          Ok(retv)
///          
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let mut _v8 :Vec<u8> = Vec::new();
///          let mut encv :Vec<u8>;
///          
///          encv = self.classid.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          encv = self.serializeddata.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          Ok(_v8)
///          
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          let mut s :String;
///          s = asn1_format_line(tab,&format!("{} SpcSerializedObject", name));
///          iowriter.write(s.as_bytes())?;
///          
///          s = format!("classid");
///          self.classid.print_asn1(&s,tab + 1, iowriter)?;
///          
///          s = format!("serializeddata");
///          self.serializeddata.print_asn1(&s,tab + 1, iowriter)?;
///          
///          Ok(())
///          
///      }
///      
///  }
///  
///  pub struct SpcLink
///  {
///      pub stype : i32, 
///      pub url : Asn1ImpSet<Asn1OctData, 0>, 
///      pub moniker :   Asn1ImpSet<SpcSerializedObject, 1>, 
///      pub file : Asn1ImpSet<SpcString,2>,
///  }
///  asn1obj_error_class!{SpcLinkfsdJjYNtcxy2KBuyError}
///   
///  impl Asn1Op for SpcLink {
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mut mainv :serde_json::value::Value = serde_json::json!({});
///          let mut idx :i32 = 0;
///          let mut cint :Asn1Integer = Asn1Integer::init_asn1();
///           
///          cint.val = self.stype as i64;
///          idx += cint.encode_json("stype",&mut mainv)?;
///           
///          if self.stype == 1 {
///              idx += self.moniker.encode_json("moniker",&mut mainv)?;
///          } else if self.stype == 0 {
///              idx += self.url.encode_json("url",&mut mainv)?;
///          } else if self.stype == 2 {
///              idx += self.file.encode_json("file",&mut mainv)?;
///          } else {
///              asn1obj_new_error!{SpcLinkfsdJjYNtcxy2KBuyError,"not support {} value",self.stype}
///          }
///           
///          if key.len() > 0 {
///              val[key] = mainv;
///          } else {
///              *val = mainv;
///          }
///           
///          return Ok(idx);
///      }
///      
///      fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mainv :serde_json::value::Value;
///          let mut idx :i32=0;
///          let mut cint :Asn1Integer = Asn1Integer::init_asn1();
///           
///          if key.len() > 0 {
///              let k = val.get(key);
///              if k.is_none() {
///                  self.stype = -1;
///                  self.url = Asn1ImpSet::init_asn1();
///                  self.moniker = Asn1ImpSet::init_asn1();
///                  self.file = Asn1ImpSet::init_asn1();
///                  return Ok(0);
///              }
///              mainv = serde_json::json!(k.clone());
///          } else {
///              mainv = val.clone();
///          }
///           
///          if !mainv.is_object() {
///              asn1obj_new_error!{SpcLinkfsdJjYNtcxy2KBuyError,"not object to decode"}
///          }
///           
///          idx += cint.decode_json("stype",&mainv)?;
///          self.stype = cint.val as i32;
///           
///          if self.stype == 1 {
///              idx += self.moniker.decode_json("moniker",&mainv)?;
///          } else if self.stype == 0 {
///              idx += self.url.decode_json("url",&mainv)?;
///          } else if self.stype == 2 {
///              idx += self.file.decode_json("file",&mainv)?;
///          } else {
///              asn1obj_new_error!{SpcLinkfsdJjYNtcxy2KBuyError,"not support {} value decode",self.stype}
///          }
///           
///          return Ok(idx);
///      }
///      
///      fn init_asn1() -> Self {
///          SpcLink {
///              stype : -1,
///              url : Asn1ImpSet::init_asn1(),
///              moniker : Asn1ImpSet::init_asn1(),
///              file : Asn1ImpSet::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut ores : Result<usize,Box<dyn Error>>;
///           
///          ores = self.moniker.decode_asn1(code);
///          if ores.is_ok() {
///              self.stype = 1;
///              return Ok(ores.unwrap());
///          }
///           
///          ores = self.url.decode_asn1(code);
///          if ores.is_ok() {
///              self.stype = 0;
///              return Ok(ores.unwrap());
///          }
///           
///          ores = self.file.decode_asn1(code);
///          if ores.is_ok() {
///              self.stype = 2;
///              return Ok(ores.unwrap());
///          }
///           
///          asn1obj_new_error!{SpcLinkfsdJjYNtcxy2KBuyError,"not supported type"}
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let retv :Vec<u8>;
///           
///          if self.stype == 1 {
///              retv = self.moniker.encode_asn1()?;
///          } else if self.stype == 0 {
///              retv = self.url.encode_asn1()?;
///          } else if self.stype == 2 {
///              retv = self.file.encode_asn1()?;
///          } else {
///              asn1obj_new_error!{SpcLinkfsdJjYNtcxy2KBuyError,"not supported type {}", self.stype}
///          }
///           
///          Ok(retv)
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          let  s :String;
///           
///          s = asn1_format_line(tab,&format!("{}.stype type {}",name,self.stype));
///          iowriter.write(s.as_bytes())?;
///           
///          if self.stype == 1 {
///              self.moniker.print_asn1("moniker",tab+1,iowriter)?;
///          } else if self.stype == 0 {
///              self.url.print_asn1("url",tab+1,iowriter)?;
///          } else if self.stype == 2 {
///              self.file.print_asn1("file",tab+1,iowriter)?;
///          } else {
///              asn1obj_new_error!{SpcLinkfsdJjYNtcxy2KBuyError,"not supported type {}", self.stype}
///          }
///           
///          Ok(())
///      }
///  }
///  ```
#[proc_macro_attribute]
pub fn asn1_int_choice(_attr :TokenStream, item :TokenStream) -> TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let co :syn::DeriveInput;
	let nargs = _attr.clone();
	let sname :String;
	let mut cs :IntChoiceSyn = syn::parse_macro_input!(nargs as IntChoiceSyn);

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

///  macro to expand choice of ASN.1 structure
///  example
///  ```rust
///  use asn1obj_codegen::{asn1_sequence,asn1_obj_selector,asn1_choice};
///  use asn1obj::{asn1obj_error_class,asn1obj_new_error};
///  use asn1obj::base::*;
///  use asn1obj::complex::*;
///  use asn1obj::asn1impl::{Asn1Op,Asn1Selector};
///   use asn1obj::strop::asn1_format_line;
///  
///  use num_bigint::{BigUint};
///  use hex::FromHex;
///  use std::error::Error;
///  use std::io::Write;
///  use serde_json;
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1RsaPubkeyElem {
///  	pub n :Asn1BigNum,
///  	pub e :Asn1BigNum,
///  }
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1RsaPubkey {
///  	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
///  }
///  
///  
///  
///  #[asn1_obj_selector(selector=val,any=default,rsa="1.2.840.113549.1.1.1")]
///  #[derive(Clone)]
///  pub struct Asn1X509PubkeySelector {
///  	pub val : Asn1Object,
///  	pub padded : Asn1Any,
///  }
///  
///  #[asn1_choice(selector=valid)]
///  #[derive(Clone)]
///  pub struct Asn1X509PubkeyElem {
///  	pub valid : Asn1SeqSelector<Asn1X509PubkeySelector>,
///  	pub rsa : Asn1BitSeq<Asn1RsaPubkey>,
///  	pub any : Asn1Any,
///  }
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1X509Pubkey {
///  	pub elem :Asn1Seq<Asn1X509PubkeyElem>,
///  }
///  
///  fn format_vecs(buf :&[u8], tab :i32) -> String {
///  	let mut outs :String = "".to_string();
///  	let mut lasti : usize = 0;
///  	let mut ki :usize;
///  	for i in 0..buf.len() {
///  		if (i%16) == 0 {
///  			if i > 0 {
///  				outs.push_str("    ");
///  				while lasti != i {
///  					if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
///  						outs.push(buf[lasti] as char);
///  					} else {
///  						outs.push_str(".");
///  					}
///  					lasti += 1;
///  				}
///  				outs.push_str("\n");
///  			}
///  
///  			for _j in 0..tab {
///  				outs.push_str("    ");
///  			}
///  		}
///  		if (i % 16) == 0 {
///  			outs.push_str(&format!("{:02x}", buf[i]));	
///  		} else {
///  			outs.push_str(&format!(":{:02x}", buf[i]));	
///  		}
///  		
///  	}
///  
///  	if lasti != buf.len() {
///  		ki = buf.len();
///  		while (ki % 16) != 0 {
///  			outs.push_str("   ");
///  			ki += 1;
///  		}
///  		outs.push_str("    ");
///  		while lasti != buf.len() {
///  			if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
///  				outs.push(buf[lasti] as char);
///  			} else {
///  				outs.push_str(".");
///  			}
///  			lasti += 1;
///  		}
///  	}
///  	outs.push_str("\n");
///  	return outs;
///  }
///  
///  fn main() -> Result<(),Box<dyn Error>> {
///  	let mut pubkey :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
///  	let mut pubkeyelem :Asn1RsaPubkeyElem = Asn1RsaPubkeyElem::init_asn1();
///  	let nv :Vec<u8> = Vec::from_hex("df45f6d9925fe470dcb55c26afe0dfd6a0307cf9287342749b7341b342f87fa2b5238245ac73788b0016015834c59fd0481cb9cb97f575f13abd600799b3a2113ec2e4c22385fd45674326ffc55fa84ab2088063f48e8efeb7dd473194a079fabd96d4f59f70ccc0bb78628bc89725519cd57a180e54fd6608ef2d401124ed5e23598329eb13e2dd0ebdd7692bff9a07ce57ec50b1b3bc6d585d2585f96fc9276ed2d36b834420bd1b96f7a4e2b913795fe8744a2046ba537b18104ee98a8b7b959e009742091814211b15c6a5992f46c5a74b9398a47b01d20fc35228f174c617ca3ab2e89944147150c24c7619db1666bf0d447630683dea078274d8d3069d")?;
///  	let ne :Vec<u8> = Vec::from_hex("010001")?;
///  	pubkeyelem.n.val = BigUint::from_bytes_be(&nv);
///  	pubkeyelem.e.val = BigUint::from_bytes_be(&ne);
///  	pubkey.elem.val.push(pubkeyelem);
///  	let mut pubelem : Asn1X509PubkeyElem = Asn1X509PubkeyElem::init_asn1();
///  	let mut x509pub :Asn1X509Pubkey = Asn1X509Pubkey::init_asn1();
///  	pubelem.valid.val.val.set_value("1.2.840.113549.1.1.1")?;
///  	pubelem.rsa.val = pubkey.clone();
///  	x509pub.elem.val.push(pubelem);	
///  	let outd = x509pub.encode_asn1()?;
///  	let outs = format!("output encode data\n{}",format_vecs(&outd,1));
///  	std::io::stdout().write(outs.as_bytes())?;
///  	let mut outf  = std::io::stdout();
///  	x509pub.print_asn1("X509 Public Key",0,&mut outf)?;
///  	Ok(())
///  
///  }
///  /*
///  output:
///  output encode data
///      30:82:01:22:30:0d:06:09:2a:86:48:86:f7:0d:01:01    0.."0...*.H.....
///      01:00:00:03:82:01:0f:00:30:82:01:0a:02:82:01:01    ........0.......
///      00:df:45:f6:d9:92:5f:e4:70:dc:b5:5c:26:af:e0:df    ..E..._.p..\&...
///      d6:a0:30:7c:f9:28:73:42:74:9b:73:41:b3:42:f8:7f    ..0|.(sBt.sA.B..
///      a2:b5:23:82:45:ac:73:78:8b:00:16:01:58:34:c5:9f    ..#.E.sx....X4..
///      d0:48:1c:b9:cb:97:f5:75:f1:3a:bd:60:07:99:b3:a2    .H.....u.:.`....
///      11:3e:c2:e4:c2:23:85:fd:45:67:43:26:ff:c5:5f:a8    .>...#..EgC&.._.
///      4a:b2:08:80:63:f4:8e:8e:fe:b7:dd:47:31:94:a0:79    J...c......G1..y
///      fa:bd:96:d4:f5:9f:70:cc:c0:bb:78:62:8b:c8:97:25    ......p...xb...%
///      51:9c:d5:7a:18:0e:54:fd:66:08:ef:2d:40:11:24:ed    Q..z..T.f..-@.$.
///      5e:23:59:83:29:eb:13:e2:dd:0e:bd:d7:69:2b:ff:9a    ^#Y.).......i+..
///      07:ce:57:ec:50:b1:b3:bc:6d:58:5d:25:85:f9:6f:c9    ..W.P...mX]%..o.
///      27:6e:d2:d3:6b:83:44:20:bd:1b:96:f7:a4:e2:b9:13    'n..k.D ........
///      79:5f:e8:74:4a:20:46:ba:53:7b:18:10:4e:e9:8a:8b    y_.tJ F.S{..N...
///      7b:95:9e:00:97:42:09:18:14:21:1b:15:c6:a5:99:2f    {....B...!...../
///      46:c5:a7:4b:93:98:a4:7b:01:d2:0f:c3:52:28:f1:74    F..K...{....R(.t
///      c6:17:ca:3a:b2:e8:99:44:14:71:50:c2:4c:76:19:db    ...:...D.qP.Lv..
///      16:66:bf:0d:44:76:30:68:3d:ea:07:82:74:d8:d3:06    .f..Dv0h=...t...
///      9d:02:03:01:00:01                                  ......
///  X509 Public Key[0] ASN1_CHOICE Asn1X509PubkeyElem
///      [valid]Asn1SeqSelector Asn1X509PubkeySelector
///          val: ASN1_OBJECT 1.2.840.113549.1.1.1
///          padded: ASN1_ANY tag 0x00 0 
///      rsa Asn1BitSeq[0] Asn1RsaPubkeyElem
///          n: ASN1_BIGNUM
///              df:45:f6:d9:92:5f:e4:70:dc:b5:5c:26:af:e0:df:d6    .E..._.p..\&....
///              a0:30:7c:f9:28:73:42:74:9b:73:41:b3:42:f8:7f:a2    .0|.(sBt.sA.B...
///              b5:23:82:45:ac:73:78:8b:00:16:01:58:34:c5:9f:d0    .#.E.sx....X4...
///              48:1c:b9:cb:97:f5:75:f1:3a:bd:60:07:99:b3:a2:11    H.....u.:.`.....
///              3e:c2:e4:c2:23:85:fd:45:67:43:26:ff:c5:5f:a8:4a    >...#..EgC&.._.J
///              b2:08:80:63:f4:8e:8e:fe:b7:dd:47:31:94:a0:79:fa    ...c......G1..y.
///              bd:96:d4:f5:9f:70:cc:c0:bb:78:62:8b:c8:97:25:51    .....p...xb...%Q
///              9c:d5:7a:18:0e:54:fd:66:08:ef:2d:40:11:24:ed:5e    ..z..T.f..-@.$.^
///              23:59:83:29:eb:13:e2:dd:0e:bd:d7:69:2b:ff:9a:07    #Y.).......i+...
///              ce:57:ec:50:b1:b3:bc:6d:58:5d:25:85:f9:6f:c9:27    .W.P...mX]%..o.'
///              6e:d2:d3:6b:83:44:20:bd:1b:96:f7:a4:e2:b9:13:79    n..k.D ........y
///              5f:e8:74:4a:20:46:ba:53:7b:18:10:4e:e9:8a:8b:7b    _.tJ F.S{..N...{
///              95:9e:00:97:42:09:18:14:21:1b:15:c6:a5:99:2f:46    ....B...!...../F
///              c5:a7:4b:93:98:a4:7b:01:d2:0f:c3:52:28:f1:74:c6    ..K...{....R(.t.
///              17:ca:3a:b2:e8:99:44:14:71:50:c2:4c:76:19:db:16    ..:...D.qP.Lv...
///              66:bf:0d:44:76:30:68:3d:ea:07:82:74:d8:d3:06:9d    f..Dv0h=...t....
///          e: ASN1_BIGNUM 0x00010001
///  */
///  ```
///  internal handle
///  ```rust
///  #[asn1_obj_selector(selector=val,any=default,rsa="1.2.840.113549.1.1.1")]
///  #[derive(Clone)]
///  pub struct Asn1X509PubkeySelector {
///  	pub val : Asn1Object,
///  	pub padded : Asn1Any,
///  }
///  
///  #[asn1_choice(selector=valid)]
///  #[derive(Clone)]
///  pub struct Asn1X509PubkeyElem {
///  	pub valid : Asn1SeqSelector<Asn1X509PubkeySelector>,
///  	pub rsa : Asn1BitSeq<Asn1RsaPubkey>,
///  	pub any : Asn1Any,
///  }
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1X509Pubkey {
///  	pub elem :Asn1Seq<Asn1X509PubkeyElem>,
///  }
///  ```
///  transfer into
///  ```rust
///  
///  
///  #[derive(Clone)] 
///  pub struct Asn1X509PubkeySelector
///  { 
///  	pub val : Asn1Object, 
///  	pub padded : Asn1Any, 
///  }
///  asn1obj_error_class!{ Asn1X509PubkeySelectorError8tSlTLiOEa7miZ9x3PmD }
///  
///  impl Asn1Selector for Asn1X509PubkeySelector {
///      
///      fn encode_select(&self) -> Result<String,Box<dyn Error>> {
///          let k = format!("{}",self.val.get_value());
///          let retv :String;
///          
///          if k == "1.2.840.113549.1.1.1" || k == "1.2.840.113549.1.1.1" {
///              retv = format!("rsa");
///          } else {
///              retv = format!("any");
///          }
///          Ok(retv)
///      }
///      
///      fn decode_select(&self) -> Result<String,Box<dyn Error>> {
///          let k = format!("{}",self.val.get_value());
///          let retv :String;
///          
///          if k == "1.2.840.113549.1.1.1" || k == "1.2.840.113549.1.1.1" {
///              retv = format!("rsa");
///          } else {
///              retv = format!("any");
///          }
///          Ok(retv)
///      }
///      
///  }
///  
///  impl Asn1Op for Asn1X509PubkeySelector {
///      
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mut mainv = serde_json::json!({});
///          let mut idx :i32 = 0;
///           
///          idx += self.val.encode_json("val",&mut mainv)?;
///          idx += self.padded.encode_json("padded",&mut mainv)?;
///           
///          if key.len() > 0 {
///              val[key] = mainv;
///          } else {
///              *val = mainv;
///          }
///           
///          Ok(idx)
///          
///      }
///      
///      fn decode_json(&mut self, key :&str,val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mainv : serde_json::value::Value;
///          let mut idx :i32 = 0;
///           
///          if key.len() > 0 {
///              let k = val.get(key);
///              if k.is_none() {
///                  self.val = Asn1Object::init_asn1();
///                  self.padded = Asn1Any::init_asn1();
///                  return Ok(0);
///              }
///              mainv = serde_json::json!(k.clone());
///          } else {
///              mainv = val.clone();
///          }
///           
///          if !mainv.is_object() {
///              asn1obj_new_error!{Asn1X509PubkeySelectorError8tSlTLiOEa7miZ9x3PmD,"[{}] not valid object",key}
///          }
///           
///          idx += self.val.decode_json("val",&mainv)?;
///          idx += self.padded.decode_json("padded",&mainv)?;
///           
///          return Ok(idx);
///          
///      }
///      
///      fn init_asn1() -> Self {
///          Asn1X509PubkeySelector {
///              val : Asn1Object::init_asn1(),
///              padded : Asn1Any::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut retv :usize = 0;
///          let mut _endsize :usize = code.len();
///          
///          let ro = self.val.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          let ro = self.padded.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          Ok(retv)
///          
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let mut _v8 :Vec<u8> = Vec::new();
///          let mut encv :Vec<u8>;
///          
///          encv = self.val.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          encv = self.padded.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          Ok(_v8)
///          
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          let mut s :String;
///          s = asn1_format_line(tab,&format!("{} Asn1X509PubkeySelector", name));
///          iowriter.write(s.as_bytes())?;
///          
///          s = format!("val");
///          self.val.print_asn1(&s,tab + 1, iowriter)?;
///          
///          s = format!("padded");
///          self.padded.print_asn1(&s,tab + 1, iowriter)?;
///          
///          Ok(())
///          
///      }
///      
///  }
///  
///  #[derive(Clone)] 
///  pub struct Asn1X509PubkeyElem
///  {
///      pub valid : Asn1SeqSelector<Asn1X509PubkeySelector>,
///      pub rsa : Asn1BitSeq<Asn1RsaPubkey>,
///      pub any : Asn1Any,
///  }
///  
///  asn1obj_error_class!{ Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB }
///  
///  impl Asn1Op for Asn1X509PubkeyElem {
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>>{
///          let mut mainv :serde_json::value::Value = serde_json::json!({});
///          let mut idx :i32 = 0;
///           
///          idx += self.valid.encode_json("valid",&mut mainv)?;
///          let c :String = self.valid.encode_select()?;
///          if c == "rsa" {
///              idx += self.rsa.encode_json("rsa",&mut mainv)?;
///          } else if c == "any" {
///              idx += self.any.encode_json("any",&mut mainv)?;
///          } else {
///              asn1obj_new_error!{Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB,"not support [{}]",c}
///          }
///           
///          if key.len() > 0 {
///              val[key] = mainv;
///          } else {
///              *val = mainv;
///          }
///           
///          return Ok(idx);
///      }
///      
///      fn decode_json(&mut self, key :&str,val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>>{
///          let mainv :serde_json::value::Value;
///          let mut idx :i32=0;
///          if key.len() > 0 {
///              let k = val.get(key);
///              if k.is_none() {
///                  self.valid = Asn1SeqSelector::init_asn1();
///                  self.rsa = Asn1BitSeq::init_asn1();
///                  self.any = Asn1Any::init_asn1();
///              return Ok(0);
///              }
///              mainv = serde_json::json!(k.clone());
///          } else {
///              mainv = val.clone();
///          }
///           
///          if !mainv.is_object() {
///              asn1obj_new_error!{Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB,"not object to decode"}
///          }
///           
///          idx += self.valid.decode_json("valid",&mainv)?;
///          self.rsa = Asn1BitSeq::init_asn1();
///          self.any = Asn1Any::init_asn1();
///           
///          let c :String = self.valid.decode_select()?;
///          if c == "rsa" {
///              idx += self.rsa.decode_json("rsa",&mainv)?;
///          } else if c == "any" {
///              idx += self.any.decode_json("any",&mainv)?;
///          } else {
///              asn1obj_new_error!{Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB,"not support [{}]",c}
///          }
///           
///          return Ok(idx);
///      }
///      
///      fn init_asn1() -> Self {
///          Asn1X509PubkeyElem {
///              valid : Asn1SeqSelector::init_asn1(),
///              rsa : Asn1BitSeq::init_asn1(),
///              any : Asn1Any::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut retv :usize = 0;
///          let mut _endsize :usize = code.len();
///          
///          retv += self.valid.decode_asn1(&code[retv.._endsize])?;
///          
///          let k = self.valid.decode_select()?;
///          
///          if k == "rsa" {
///              retv += self.rsa.decode_asn1(&code[retv.._endsize])?;
///          } else if k == "any" {
///              retv += self.any.decode_asn1(&code[retv.._endsize])?;
///          } else {
///              asn1obj_new_error!{ Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB, "can not find [{}] selector", k}
///          }
///          
///          Ok(retv)
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let mut retv : Vec<u8>;
///          let mut _encv : Vec<u8>;
///          
///          _encv = self.valid.encode_asn1()?;
///          
///          let k = self.valid.encode_select()?;
///          if k == "rsa" {
///              let vk = self.rsa.encode_asn1()?;
///              for i in 0..vk.len() {
///                  _encv.push(vk[i]);
///              }
///          } else if k == "any" {
///              let vk = self.any.encode_asn1()?;
///              for i in 0..vk.len() {
///                  _encv.push(vk[i]);
///              }
///          } else {
///              asn1obj_new_error!{ Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB, "can not support [{}]", k }
///          }
///          retv = Vec::new();
///          for i in 0.._encv.len() {
///              retv.push(_encv[i]);
///          }
///          
///          Ok(retv)
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          let k = self.valid.encode_select()?;
///          let _outs :String;
///          
///          _outs = asn1_format_line(tab,&format!("{} ASN1_CHOICE Asn1X509PubkeyElem",name));
///          let _ = iowriter.write(_outs.as_bytes())?;
///          
///          let selname = format!("valid");
///          let _ = self.valid.print_asn1(&selname,tab + 1, iowriter)?;
///          
///          if k == "rsa" {
///              let nname = format!("rsa");
///              let _ = self.rsa.print_asn1(&nname,tab+1, iowriter)?;
///          } else if k == "any" {
///              let nname = format!("any");
///              let _ = self.any.print_asn1(&nname,tab+1, iowriter)?;
///          } else {
///              asn1obj_new_error!{ Asn1X509PubkeyElemErrora5f1d1hX0BAHlk4uAlJB, "can not support [{}]", k }
///          }
///          Ok(())
///      }
///      
///  }
///  
///  #[derive(Clone)] 
///  pub struct Asn1X509Pubkey
///  { 
///  	pub elem : Asn1Seq<Asn1X509PubkeyElem>,
///  }
///  asn1obj_error_class!{Asn1X509PubkeyErrorfMxagY16r88PXRFI6uvY}
///  
///  impl Asn1Op for Asn1X509Pubkey {
///      
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          return self.elem.encode_json(key,val);
///      }
///      
///      fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          return self.elem.decode_json(key,val);
///      }
///      
///      fn init_asn1() -> Self {
///          Asn1X509Pubkey {
///              elem : Asn1Seq::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut retv :usize = 0;
///          let mut _endsize :usize = code.len();
///          
///          let ro = self.elem.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          Ok(retv)
///          
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let mut _v8 :Vec<u8> = Vec::new();
///          let encv :Vec<u8>;
///          
///          encv = self.elem.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          Ok(_v8)
///          
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          return self.elem.print_asn1(name,tab,iowriter);
///      }
///      
///  }
///  ```
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
		let dbgval : bool;
		if ASN1_GEN_PROC_VAR.debuglevel > 0 {
			dbgval = true;
		} else {
			dbgval = false;
		}
		SequenceSyn{
			debugenable : dbgval,
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
				rets.push_str(&format_tab_line(tab + 2,"_i = 0;"));
				rets.push_str(&format_tab_line(tab + 2,"_lasti = _i;"));
				rets.push_str(&format_tab_line(tab + 2,&format!("_outs = format!(\"{} decode at [0x{{:x}}:{{}}]\\n\",_lastv,_lastv);",k)));
				rets.push_str(&format_tab_line(tab + 2,"while (_i + _lastv) < code.len() {"));
				rets.push_str(&format_tab_line(tab + 3,"if _i >= 16 {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\"    \");"));
				rets.push_str(&format_tab_line(tab + 4,"while _lasti < _i {"));
				rets.push_str(&format_tab_line(tab + 5,"if code[(_lastv + _lasti)] >= 0x20 && code[(_lastv + _lasti)] <= 0x7e {"));
				rets.push_str(&format_tab_line(tab + 5,"_outs.push(code[(_lastv+_lasti)] as char);"));
				rets.push_str(&format_tab_line(tab + 5,"} else {"));
				rets.push_str(&format_tab_line(tab + 5,"_outs.push_str(\".\");"));
				rets.push_str(&format_tab_line(tab + 5,"}"));
				rets.push_str(&format_tab_line(tab + 5,"_lasti += 1;"));
				rets.push_str(&format_tab_line(tab + 4,"}"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\"\\n\");"));
				rets.push_str(&format_tab_line(tab + 4,"break;"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"_outs.push_str(&format!(\" 0x{:02x}\",code[_i]));"));
				rets.push_str(&format_tab_line(tab + 3,"_i += 1;"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 2,"if _i < 16 {"));
				rets.push_str(&format_tab_line(tab + 3,"while ( _i % 16) != 0 {"));
				rets.push_str(&format_tab_line(tab + 4,"_outs.push_str(\"     \");"));
				rets.push_str(&format_tab_line(tab + 4,"_i += 1;"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"while (_lasti + _lastv) < code.len() {"));
				rets.push_str(&format_tab_line(tab + 4,"if code[(_lastv + _lasti)] >= 0x20 && code[(_lastv + _lasti)] <= 0x7e {"));
				rets.push_str(&format_tab_line(tab + 5,"_outs.push(code[(_lastv+_lasti)] as char);"));
				rets.push_str(&format_tab_line(tab + 4,"} else {"));
				rets.push_str(&format_tab_line(tab + 5,"_outs.push_str(\".\");"));
				rets.push_str(&format_tab_line(tab + 4,"}"));
				rets.push_str(&format_tab_line(tab + 4,"_lasti += 1;"));
				rets.push_str(&format_tab_line(tab + 3,"}"));
				rets.push_str(&format_tab_line(tab + 3,"_outs.push_str(\"\\n\");"));
				rets.push_str(&format_tab_line(tab + 2,"}"));
				rets.push_str(&format_tab_line(tab + 2,"let _ = _outf.write(_outs.as_bytes())?;"));
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
		if self.parsenames.len() == 1 && self.is_asn1_seqname(&(self.parsenames[0])) {
			rets.push_str(&format_tab_line(tab + 1, &format!("return self.{}.print_asn1(name,tab,iowriter);",self.parsenames[0])));
		} else {
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
		}
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn is_asn1_seqname(&self,name :&str) -> bool {
		let mut retv :bool = false;
		let k2 = self.kmap.get(name);
		if k2.is_some() {
			let v2 = k2.unwrap();
			let v = extract_type_name(v2);
			if v == "Asn1Seq" {
				retv = true;
			}
		}
		return retv;
	}

	fn format_encode_json(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab,"fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		if self.parsenames.len() == 1 && self.is_asn1_seqname(&self.parsenames[0]) {
			rets.push_str(&format_tab_line(tab + 1, &format!("return self.{}.encode_json(key,val);",self.parsenames[0])));
		} else {
			rets.push_str(&format_tab_line(tab + 1, "let mut mainv :serde_json::value::Value = serde_json::json!({});"));
			rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));
			rets.push_str(&format_tab_line(tab + 1, ""));
			for k in self.parsenames.iter() {
				rets.push_str(&format_tab_line(tab + 1, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",k,k)));
			}
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, "if key.len() > 0 {"));
			rets.push_str(&format_tab_line(tab + 2, "val[key] = mainv;"));
			rets.push_str(&format_tab_line(tab + 1, "} else {"));
			rets.push_str(&format_tab_line(tab + 2, "*val = mainv;"));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, "return Ok(idx);"));			
		}
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	fn format_decode_json(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		rets.push_str(&format_tab_line(tab, "fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		if self.parsenames.len() == 1 && self.is_asn1_seqname(&(self.parsenames[0])) {
			rets.push_str(&format_tab_line(tab + 1, &format!("return self.{}.decode_json(key,val);",self.parsenames[0])));
		} else {
			rets.push_str(&format_tab_line(tab + 1, "let mainv :serde_json::value::Value;"));
			rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32=0;"));
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, "if key.len() > 0 {"));
			rets.push_str(&format_tab_line(tab + 2, "let k = val.get(key);"));
			rets.push_str(&format_tab_line(tab + 2, "if k.is_none() {"));
			for k in self.parsenames.iter() {
				let v = self.kmap.get(k).unwrap();
				rets.push_str(&format_tab_line(tab + 3, &format!("self.{} = {}::init_asn1();",k,extract_type_name(v))));
			}
			rets.push_str(&format_tab_line(tab + 3, "return Ok(0);"));
			rets.push_str(&format_tab_line(tab + 2, "}"));
			rets.push_str(&format_tab_line(tab + 2, "mainv = serde_json::json!(k.clone());"));
			rets.push_str(&format_tab_line(tab + 1, "} else {"));
			rets.push_str(&format_tab_line(tab + 2, "mainv = val.clone();"));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, "if !mainv.is_object() {"));
			rets.push_str(&format_tab_line(tab + 2, &format!("asn1obj_new_error!{{{},\"not object to decode\"}}",self.errname)));
			rets.push_str(&format_tab_line(tab + 1, "}"));
			rets.push_str(&format_tab_line(tab + 1, ""));
			for k in self.parsenames.iter() {
				rets.push_str(&format_tab_line(tab + 1, &format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",k,k)));
			}
			rets.push_str(&format_tab_line(tab + 1, ""));
			rets.push_str(&format_tab_line(tab + 1, "return Ok(idx);"));
		}
		rets.push_str(&format_tab_line(tab, "}"));
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
		rets.push_str(&self.format_encode_json(1));
		rets.push_str(&format_tab_line(1,""));
		rets.push_str(&self.format_decode_json(1));
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

///  this will expand sequence 
///  example
///  ```rust
///  use asn1obj_codegen::{asn1_sequence};
///  use asn1obj::{asn1obj_error_class,asn1obj_new_error};
///  use asn1obj::base::*;
///  use asn1obj::complex::*;
///  use asn1obj::asn1impl::Asn1Op;
///   use asn1obj::strop::asn1_format_line;
///  
///  use num_bigint::{BigUint};
///  use hex::FromHex;
///  use std::error::Error;
///  use std::io::Write;
///  use serde_json;
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1RsaPubkeyElem {
///  	pub n :Asn1BigNum,
///  	pub e :Asn1BigNum,
///  }
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1RsaPubkey {
///  	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
///  }
///  
///  fn format_vecs(buf :&[u8], tab :i32) -> String {
///  	let mut outs :String = "".to_string();
///  	let mut lasti : usize = 0;
///  	let mut ki :usize;
///  	for i in 0..buf.len() {
///  		if (i%16) == 0 {
///  			if i > 0 {
///  				outs.push_str("    ");
///  				while lasti != i {
///  					if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
///  						outs.push(buf[lasti] as char);
///  					} else {
///  						outs.push_str(".");
///  					}
///  					lasti += 1;
///  				}
///  				outs.push_str("\n");
///  			}
///  
///  			for _j in 0..tab {
///  				outs.push_str("    ");
///  			}
///  		}
///  		if (i % 16) == 0 {
///  			outs.push_str(&format!("{:02x}", buf[i]));	
///  		} else {
///  			outs.push_str(&format!(":{:02x}", buf[i]));	
///  		}
///  		
///  	}
///  
///  	if lasti != buf.len() {
///  		ki = buf.len();
///  		while (ki % 16) != 0 {
///  			outs.push_str("   ");
///  			ki += 1;
///  		}
///  		outs.push_str("    ");
///  		while lasti != buf.len() {
///  			if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
///  				outs.push(buf[lasti] as char);
///  			} else {
///  				outs.push_str(".");
///  			}
///  			lasti += 1;
///  		}
///  	}
///  	outs.push_str("\n");
///  	return outs;
///  }
///  
///  
///  fn main() -> Result<(),Box<dyn Error>> {
///  	let mut pubkey :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
///  	let mut pubkeyelem :Asn1RsaPubkeyElem = Asn1RsaPubkeyElem::init_asn1();
///  	let nv :Vec<u8> = Vec::from_hex("df45f6d9925fe470dcb55c26afe0dfd6a0307cf9287342749b7341b342f87fa2b5238245ac73788b0016015834c59fd0481cb9cb97f575f13abd600799b3a2113ec2e4c22385fd45674326ffc55fa84ab2088063f48e8efeb7dd473194a079fabd96d4f59f70ccc0bb78628bc89725519cd57a180e54fd6608ef2d401124ed5e23598329eb13e2dd0ebdd7692bff9a07ce57ec50b1b3bc6d585d2585f96fc9276ed2d36b834420bd1b96f7a4e2b913795fe8744a2046ba537b18104ee98a8b7b959e009742091814211b15c6a5992f46c5a74b9398a47b01d20fc35228f174c617ca3ab2e89944147150c24c7619db1666bf0d447630683dea078274d8d3069d")?;
///  	let ne :Vec<u8> = Vec::from_hex("010001")?;
///  	pubkeyelem.n.val = BigUint::from_bytes_be(&nv);
///  	pubkeyelem.e.val = BigUint::from_bytes_be(&ne);
///  	pubkey.elem.val.push(pubkeyelem);
///  	let outd = pubkey.encode_asn1()?;
///  	let s = format_vecs(&outd,1);
///  	let mut outs :String = "".to_string();
///  	let mut outf = std::io::stdout();
///  	outs.push_str("outs\n");
///  	outs.push_str(&s);
///  	std::io::stdout().write(outs.as_bytes())?;
///  	pubkey.print_asn1("Rsa Public Key",0,&mut outf)?;
///  	Ok(())
///  }
///  /*
///  output:
///  outs
///      30:82:01:0a:02:82:01:01:00:df:45:f6:d9:92:5f:e4    0.........E..._.
///      70:dc:b5:5c:26:af:e0:df:d6:a0:30:7c:f9:28:73:42    p..\&.....0|.(sB
///      74:9b:73:41:b3:42:f8:7f:a2:b5:23:82:45:ac:73:78    t.sA.B....#.E.sx
///      8b:00:16:01:58:34:c5:9f:d0:48:1c:b9:cb:97:f5:75    ....X4...H.....u
///      f1:3a:bd:60:07:99:b3:a2:11:3e:c2:e4:c2:23:85:fd    .:.`.....>...#..
///      45:67:43:26:ff:c5:5f:a8:4a:b2:08:80:63:f4:8e:8e    EgC&.._.J...c...
///      fe:b7:dd:47:31:94:a0:79:fa:bd:96:d4:f5:9f:70:cc    ...G1..y......p.
///      c0:bb:78:62:8b:c8:97:25:51:9c:d5:7a:18:0e:54:fd    ..xb...%Q..z..T.
///      66:08:ef:2d:40:11:24:ed:5e:23:59:83:29:eb:13:e2    f..-@.$.^#Y.)...
///      dd:0e:bd:d7:69:2b:ff:9a:07:ce:57:ec:50:b1:b3:bc    ....i+....W.P...
///      6d:58:5d:25:85:f9:6f:c9:27:6e:d2:d3:6b:83:44:20    mX]%..o.'n..k.D 
///      bd:1b:96:f7:a4:e2:b9:13:79:5f:e8:74:4a:20:46:ba    ........y_.tJ F.
///      53:7b:18:10:4e:e9:8a:8b:7b:95:9e:00:97:42:09:18    S{..N...{....B..
///      14:21:1b:15:c6:a5:99:2f:46:c5:a7:4b:93:98:a4:7b    .!...../F..K...{
///      01:d2:0f:c3:52:28:f1:74:c6:17:ca:3a:b2:e8:99:44    ....R(.t...:...D
///      14:71:50:c2:4c:76:19:db:16:66:bf:0d:44:76:30:68    .qP.Lv...f..Dv0h
///      3d:ea:07:82:74:d8:d3:06:9d:02:03:01:00:01          =...t.........
///  Rsa Public Key[0] Asn1RsaPubkeyElem
///      n: ASN1_BIGNUM
///          df:45:f6:d9:92:5f:e4:70:dc:b5:5c:26:af:e0:df:d6    .E..._.p..\&....
///          a0:30:7c:f9:28:73:42:74:9b:73:41:b3:42:f8:7f:a2    .0|.(sBt.sA.B...
///          b5:23:82:45:ac:73:78:8b:00:16:01:58:34:c5:9f:d0    .#.E.sx....X4...
///          48:1c:b9:cb:97:f5:75:f1:3a:bd:60:07:99:b3:a2:11    H.....u.:.`.....
///          3e:c2:e4:c2:23:85:fd:45:67:43:26:ff:c5:5f:a8:4a    >...#..EgC&.._.J
///          b2:08:80:63:f4:8e:8e:fe:b7:dd:47:31:94:a0:79:fa    ...c......G1..y.
///          bd:96:d4:f5:9f:70:cc:c0:bb:78:62:8b:c8:97:25:51    .....p...xb...%Q
///          9c:d5:7a:18:0e:54:fd:66:08:ef:2d:40:11:24:ed:5e    ..z..T.f..-@.$.^
///          23:59:83:29:eb:13:e2:dd:0e:bd:d7:69:2b:ff:9a:07    #Y.).......i+...
///          ce:57:ec:50:b1:b3:bc:6d:58:5d:25:85:f9:6f:c9:27    .W.P...mX]%..o.'
///          6e:d2:d3:6b:83:44:20:bd:1b:96:f7:a4:e2:b9:13:79    n..k.D ........y
///          5f:e8:74:4a:20:46:ba:53:7b:18:10:4e:e9:8a:8b:7b    _.tJ F.S{..N...{
///          95:9e:00:97:42:09:18:14:21:1b:15:c6:a5:99:2f:46    ....B...!...../F
///          c5:a7:4b:93:98:a4:7b:01:d2:0f:c3:52:28:f1:74:c6    ..K...{....R(.t.
///          17:ca:3a:b2:e8:99:44:14:71:50:c2:4c:76:19:db:16    ..:...D.qP.Lv...
///          66:bf:0d:44:76:30:68:3d:ea:07:82:74:d8:d3:06:9d    f..Dv0h=...t....
///      e: ASN1_BIGNUM 0x00010001
///  */
///  ```
///  internal expand will give
///  ```rust
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1RsaPubkeyElem {
///  	pub n :Asn1BigNum,
///  	pub e :Asn1BigNum,
///  }
///  
///  #[asn1_sequence()]
///  #[derive(Clone)]
///  pub struct Asn1RsaPubkey {
///  	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
///  }
///  ```
///  transfer into
///  ```rust
///  #[derive(Clone)] 
///  pub struct Asn1RsaPubkeyElem
///  { 
///  	pub n : Asn1BigNum, 
///  	pub e : Asn1BigNum, 
///  }
///  asn1obj_error_class!{Asn1RsaPubkeyElemErrorirA3TA53xxy7S7zLrKwv}
///  
///  impl Asn1Op for Asn1RsaPubkeyElem {
///      
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mut mainv :serde_json::value::Value = serde_json::json!({});
///          let mut idx :i32 = 0;
///          
///          idx += self.n.encode_json("n",&mut mainv)?;
///          idx += self.e.encode_json("e",&mut mainv)?;
///          
///          if key.len() > 0 {
///              val[key] = mainv;
///          } else {
///              *val = mainv;
///          }
///          
///          return Ok(idx);
///      }
///      
///      fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          let mainv :serde_json::value::Value;
///          let mut idx :i32=0;
///          
///          if key.len() > 0 {
///              let k = val.get(key);
///              if k.is_none() {
///                  self.n = Asn1BigNum::init_asn1();
///                  self.e = Asn1BigNum::init_asn1();
///                  return Ok(0);
///              }
///              mainv = serde_json::json!(k.clone());
///          } else {
///              mainv = val.clone();
///          }
///          
///          if !mainv.is_object() {
///              asn1obj_new_error!{Asn1RsaPubkeyElemErrorirA3TA53xxy7S7zLrKwv,"not object to decode"}
///          }
///          
///          idx += self.n.decode_json("n",&mainv)?;
///          idx += self.e.decode_json("e",&mainv)?;
///          
///          return Ok(idx);
///      }
///      
///      fn init_asn1() -> Self {
///          Asn1RsaPubkeyElem {
///              n : Asn1BigNum::init_asn1(),
///              e : Asn1BigNum::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut retv :usize = 0;
///          let mut _endsize :usize = code.len();
///          
///          let ro = self.n.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          let ro = self.e.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          Ok(retv)
///          
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let mut _v8 :Vec<u8> = Vec::new();
///          let mut encv :Vec<u8>;
///          
///          encv = self.n.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          encv = self.e.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          Ok(_v8)
///          
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          let mut s :String;
///          s = asn1_format_line(tab,&format!("{} Asn1RsaPubkeyElem", name));
///          iowriter.write(s.as_bytes())?;
///          
///          s = format!("n");
///          self.n.print_asn1(&s,tab + 1, iowriter)?;
///          
///          s = format!("e");
///          self.e.print_asn1(&s,tab + 1, iowriter)?;
///          
///          Ok(())
///          
///      }
///      
///  }
///  
///  #[derive(Clone)] 
///  pub struct Asn1RsaPubkey
///  { 
///  	pub elem : Asn1Seq<Asn1RsaPubkeyElem>,
///  }
///  asn1obj_error_class!{Asn1RsaPubkeyErrorLeX1rgAPZSgrNzFkQurX}
///  
///  impl Asn1Op for Asn1RsaPubkey {
///      
///      fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          return self.elem.encode_json(key,val);
///      }
///      
///      fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///          return self.elem.decode_json(key,val);
///      }
///      
///      fn init_asn1() -> Self {
///          Asn1RsaPubkey {
///              elem : Asn1Seq::init_asn1(),
///          }
///      }
///      
///      fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///          let mut retv :usize = 0;
///          let mut _endsize :usize = code.len();
///          
///          let ro = self.elem.decode_asn1(&code[retv.._endsize]);
///          if ro.is_err() {
///              let e = ro.err().unwrap();
///              return Err(e);
///          }
///          retv += ro.unwrap();
///          
///          Ok(retv)
///          
///      }
///      
///      fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///          let mut _v8 :Vec<u8> = Vec::new();
///          let encv :Vec<u8>;
///          
///          encv = self.elem.encode_asn1()?;
///          for i in 0..encv.len() {
///              _v8.push(encv[i]);
///          }
///          
///          Ok(_v8)
///          
///      }
///      
///      fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///          return self.elem.print_asn1(name,tab,iowriter);
///      }
///      
///  }
///  ```
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
