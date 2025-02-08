
#[allow(unused_imports)]
use crate::*;
use std::collections::HashMap;
use crate::vars::{asn1_gen_debug_level};
use crate::logger::{asn1_gen_debug_out};
use crate::randv::{get_random_bytes};
use crate::kv::{SynKV};
use crate::asn1ext::{filter_attrib};
use crate::consts::{ASN1_INITFN,ASN1_JSON_ALIAS,ASN1_JSON_SKIP};
use std::error::Error;
use crate::utils::{format_tab_line,extract_type_name};
use quote::{ToTokens};

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
	omitnames :Vec<String>,
	komitfns :HashMap<String,String>,
	mapjsonalias :HashMap<String,String>,
	mapjsonskip :HashMap<String,bool>,
}

//#[allow(unused_variables)]
//#[allow(unused_mut)]
impl ObjSelectorSyn {
	pub fn new() -> Self {
		let dbgval : bool;
		if asn1_gen_debug_level() > 0 {
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
			omitnames :vec![],
			komitfns :HashMap::new(),
			mapjsonalias :HashMap::new(),
			mapjsonskip : HashMap::new(),
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
		for k in self.omitnames.iter() {
			let v = self.komitfns.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2, &format!("{} : {}(),", k,v)));
		}
		rets.push_str(&format_tab_line(tab + 1,"}"));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}

	pub fn set_init_func(&mut self,k:&str,v:&str) {
		self.omitnames.push(format!("{}",k));
		self.komitfns.insert(format!("{}",k),format!("{}",v));
	}

	pub fn set_json_alias(&mut self,n :&str, aliasname :&str) {
		self.mapjsonalias.insert(format!("{}",n),format!("{}",aliasname));
		return;
	}

	pub fn set_json_skip(&mut self, n:&str, skip :bool) {
		self.mapjsonskip.insert(format!("{}",n),skip);
		return;
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
				let jsonalias = self._get_json_alias(k);
				rets.push_str(&format_tab_line(tab + 1, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",k,jsonalias)));
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
				let jsonalias = self._get_json_alias(k);
				rets.push_str(&format_tab_line(tab + 1,&format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",k,jsonalias)));
			}
			rets.push_str(&format_tab_line(tab + 1, " "));
			rets.push_str(&format_tab_line(tab + 1, "return Ok(idx);"));
		}
		/*now to */
		rets.push_str(&format_tab_line(tab + 1, ""));
		rets.push_str(&format_tab_line(tab,"}"));
		return rets;
	}


	fn _get_json_alias(&self,k :&str) -> String {
		match self.mapjsonskip.get(k) {
			Some(v) => {
				/*to skip for this*/
				if *v {
					return format!("");
				}
			},
			_ => {}
		}

		match self.mapjsonalias.get(k) {
			Some(v) => {
				return format!("{}",v);
			}
			_ => {


				return format!("{}",k);
			}
		}
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

pub fn asn1_obj_selector(_attr :proc_macro::TokenStream,item :proc_macro::TokenStream) -> proc_macro::TokenStream {
	//asn1_gen_log_trace!("item\n{}",item.to_string());
	let nargs = _attr.clone();
	let mut co :syn::DeriveInput;
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
		syn::Data::Struct(ref mut _vv) => {
			match _vv.fields {
				syn::Fields::Named(ref mut _n) => {
					for _v in _n.named.iter_mut() {
						let mut callfn :Option<String> = None;
						let mut omitname :Option<String> = None;
						let n :String;
						let tn :String;
						let retkv :SynKV;
						let ores = filter_attrib(_v);
						if ores.is_err() {
							asn1_syn_error_fmt!("{:?}",ores.err().unwrap());
						}
						(n,tn,retkv)= ores.unwrap();
						let ores = retkv.get_value(ASN1_INITFN);
						if ores.is_some() {
							callfn = Some(format!("{}",ores.unwrap()));
							omitname = Some(format!("{}",n));
						}

						let ores = retkv.get_value(ASN1_JSON_ALIAS);
						if ores.is_some() {
							let alias = ores.unwrap();
							selcs.set_json_alias(&n,&alias);
						}

						let ores = retkv.get_value(ASN1_JSON_SKIP);
						if ores.is_some() {
							let val = format!("{}",ores.unwrap());
							asn1_gen_log_trace!("jsonskip {}",val);
							if val == "true" {
								selcs.set_json_skip(&n,true);
							}
						}

						if callfn.is_none() && n.len() > 0 && tn.len() > 0 {
							asn1_gen_log_trace!("set name [{}]=[{}]",n,tn);
							let ores = selcs.set_member(&n,&tn);
							if ores.is_err() {
								asn1_syn_error_fmt!("{:?}",ores.err().unwrap());
							}
						} else if callfn.is_some() && omitname.is_some() {
							asn1_gen_log_trace!("n[{}]=[{}]",omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
							selcs.set_init_func(omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
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
    let ntok  = co.to_token_stream();
    let mut cc = ntok.to_string();
    cc.push_str("\n");
    cc.push_str(&(selcs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}
