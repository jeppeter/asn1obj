
use std::collections::HashMap;
use crate::vars::{asn1_gen_debug_level};
use std::error::Error;
use crate::randv::{get_random_bytes};
use crate::logger::{asn1_gen_debug_out};
use crate::kv::{SynKV};
use crate::asn1ext::{filter_attrib};
use crate::consts::{ASN1_INITFN,ASN1_JSON_ALIAS,ASN1_JSON_SKIP};
use crate::utils::{format_tab_line,extract_type_name};
use quote::{ToTokens};

struct ChoiceSyn {
	debugenable : bool,
	sname : String,
	selname :String,
	errname :String,
	parsenames :Vec<String>,
	typemap :HashMap<String,String>,
	omitnames :Vec<String>,
	komitfns :HashMap<String,String>,
	mapjsonalias :HashMap<String,String>,
	mapjsonskip :HashMap<String,bool>,	
}

asn1_gen_error_class!{ChoiceSynError}

impl ChoiceSyn {
	pub fn new() -> Self {
		let dbgval : bool;
		if asn1_gen_debug_level() > 0 {
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
			omitnames : vec![],
			komitfns :HashMap::new(),
			mapjsonalias :HashMap::new(),
			mapjsonskip :HashMap::new(),
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

		for k in self.omitnames.iter() {
			let v = self.komitfns.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2, &format!("{} : {}(),", k,v)));
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


	fn format_encode_json(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		let mut idx :usize;
		let mut sidx :usize;
		rets.push_str(&format_tab_line(tab,"fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>>{"));
		rets.push_str(&format_tab_line(tab + 1, "let mut mainv :serde_json::value::Value = serde_json::json!({});"));
		rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));
		rets.push_str(&format_tab_line(tab + 1, " "));
		let jsonk = self._get_json_alias(&self.selname);
		rets.push_str(&format_tab_line(tab + 1, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",self.selname,jsonk)));
		rets.push_str(&format_tab_line(tab + 1, &format!("let c :String = self.{}.encode_select()?;",self.selname)));
		idx = 0;
		sidx = 0;
		while idx < self.parsenames.len() {
			let jsonk :String = self._get_json_alias(&self.parsenames[idx]);
			if self.parsenames[idx] != self.selname {
				if sidx > 0 {
					rets.push_str(&format_tab_line(tab+1,&format!("}} else if c == \"{}\" {{",self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab+1,&format!("if c == \"{}\" {{",self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2,&format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",self.parsenames[idx],jsonk)));
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
		let jsonk = self._get_json_alias(&self.selname);
		rets.push_str(&format_tab_line(tab + 1,&format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",self.selname,jsonk)));
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
			let jsonk :String = self._get_json_alias(&self.parsenames[idx]);
			if self.parsenames[idx] != self.selname {
				if sidx > 0 {
					rets.push_str(&format_tab_line(tab + 1,&format!("}} else if c == \"{}\" {{", self.parsenames[idx])));
				} else {
					rets.push_str(&format_tab_line(tab + 1,&format!("if c == \"{}\" {{", self.parsenames[idx])));
				}
				rets.push_str(&format_tab_line(tab + 2,&format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",self.parsenames[idx],jsonk)));
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
	omitnames :Vec<String>,
	komitfns :HashMap<String,String>,
	mapjsonalias :HashMap<String,String>,
	mapjsonskip :HashMap<String,bool>,
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
			debugenable : asn1_gen_debug_level(),
			omitnames :vec![],
			komitfns :HashMap::new(),
			mapjsonalias :HashMap::new(),
			mapjsonskip : HashMap::new(),
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

		for c in self.omitnames.iter() {
			let v = self.komitfns.get(c).unwrap();
			rets.push_str(&format_tab_line(tab + 2,&format!("{} : {}(),", c,v)));
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


	fn format_encode_json(&self,tab :i32) -> Result<String,Box<dyn Error>> {
		let mut rets :String = "".to_string();
		let mut idx :usize;
		rets.push_str(&format_tab_line(tab,"fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {"));
		rets.push_str(&format_tab_line(tab + 1, "let mut mainv :serde_json::value::Value = serde_json::json!({});"));
		rets.push_str(&format_tab_line(tab + 1, "let mut idx :i32 = 0;"));
		rets.push_str(&format_tab_line(tab + 1, "let mut cint :Asn1Integer = Asn1Integer::init_asn1();"));
		rets.push_str(&format_tab_line(tab + 1, " "));
		rets.push_str(&format_tab_line(tab + 1, &format!("cint.val = self.{} as i64;",self.seltypename)));
		let jsonk :String = self._get_json_alias(&self.seltypename);
		rets.push_str(&format_tab_line(tab + 1, &format!("idx += cint.encode_json(\"{}\",&mut mainv)?;",jsonk)));
		rets.push_str(&format_tab_line(tab + 1, " "));
		idx = 0;
		for (k,v) in self.typmaps.iter() { 
			let jsonk = self._get_json_alias(&k);
			if idx > 0 {
				rets.push_str(&format_tab_line(tab + 1,&format!("}} else if self.{} == {} {{",self.seltypename,v)));
			} else {
				rets.push_str(&format_tab_line(tab + 1,&format!("if self.{} == {} {{",self.seltypename,v)));
			}
			rets.push_str(&format_tab_line(tab + 2, &format!("idx += self.{}.encode_json(\"{}\",&mut mainv)?;",k,jsonk)));	
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
		let jsonk = self._get_json_alias(&self.seltypename);
		rets.push_str(&format_tab_line(tab+1,&format!("idx += cint.decode_json(\"{}\",&mainv)?;",jsonk)));
		rets.push_str(&format_tab_line(tab+1,&format!("self.{} = cint.val as i32;",self.seltypename)));
		rets.push_str(&format_tab_line(tab+1," "));
		idx = 0;
		for (k,v) in self.typmaps.iter() { 
			let jsonk = self._get_json_alias(&k);
			if idx > 0 {
				rets.push_str(&format_tab_line(tab + 1,&format!("}} else if self.{} == {} {{",self.seltypename,v)));
			} else {
				rets.push_str(&format_tab_line(tab + 1,&format!("if self.{} == {} {{",self.seltypename,v)));
			}
			rets.push_str(&format_tab_line(tab + 2, &format!("idx += self.{}.decode_json(\"{}\",&mainv)?;",k,jsonk)));	
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

pub fn asn1_choice(_attr : proc_macro::TokenStream,item : proc_macro::TokenStream) -> proc_macro::TokenStream {
	//asn1_gen_log_trace!("item\n{}",item.to_string());
	let mut co :syn::DeriveInput;
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
							let jsonk = ores.unwrap();
							asn1_gen_log_trace!("n {} jsonk {}",n,jsonk);
							cs.set_json_alias(&n,&jsonk);
						}

						let ores = retkv.get_value(ASN1_JSON_SKIP);
						if ores.is_some() {
							let val = format!("{}",ores.unwrap());
							asn1_gen_log_trace!("jsonskip {}",val);
							if val == "true" {
								cs.set_json_skip(&n,true);
							}
						}

						if callfn.is_none() && n.len() > 0 && tn.len() > 0 {
							asn1_gen_log_trace!("set name [{}]=[{}]",n,tn);
							cs.set_name(&n,&tn);
						} else if callfn.is_some() && omitname.is_some() {
							asn1_gen_log_trace!("n[{}]=[{}]",omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
							cs.set_init_func(omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
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
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}

pub fn asn1_int_choice(_attr : proc_macro::TokenStream, item : proc_macro::TokenStream) -> proc_macro::TokenStream {
	asn1_gen_log_trace!("item\n{}",item.to_string());
	let mut co :syn::DeriveInput;
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
		syn::Data::Struct(ref mut _vv) => {
			match _vv.fields {
				syn::Fields::Named(ref mut _n) => {
					for _v in _n.named.iter_mut() {
						let mut callfn :Option<String> = None;
						let mut omitname :Option<String> = None;
						let n :String;
						let tn :String;
						let retkv :SynKV;
						(n,tn,retkv)= filter_attrib(_v).unwrap();
						let ores = retkv.get_value(ASN1_INITFN);
						if ores.is_some() {
							callfn = Some(format!("{}",ores.unwrap()));
							omitname = Some(format!("{}",n));
						}

						let ores = retkv.get_value(ASN1_JSON_ALIAS);
						if ores.is_some() {
							let jsonk = ores.unwrap();
							asn1_gen_log_trace!("n {} jsonk {}",n,jsonk);
							cs.set_json_alias(&n,&jsonk);
						}

						let ores = retkv.get_value(ASN1_JSON_SKIP);
						if ores.is_some() {
							let val = format!("{}",ores.unwrap());
							asn1_gen_log_trace!("jsonskip {}",val);
							if val == "true" {
								cs.set_json_skip(&n,true);
							}
						}

						if callfn.is_none() && n.len() > 0 && tn.len() > 0 {
							asn1_gen_log_trace!("set name [{}]=[{}]",n,tn);
							cs.set_name(&n,&tn);
						} else if callfn.is_some() && omitname.is_some() {
							asn1_gen_log_trace!("n[{}]=[{}]",omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
							cs.set_init_func(omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
						}


						/*
						let res = get_name_type(_v.clone());
						if res.is_err() {
							asn1_syn_error_fmt!("{:?}",res.err().unwrap());
						}
						let (n,tn) = res.unwrap();
						cs.set_name(&n,&tn);
						*/
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
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}
