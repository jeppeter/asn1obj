
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
