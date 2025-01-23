
asn1_gen_error_class!{SequenceSynError}

struct SequenceSyn {
	debugenable : bool,
	sname :String,
	errname :String,
	omitnames :Vec<String>,
	parsenames :Vec<String>,
	kmap :HashMap<String,String>,
	komitinitfns :HashMap<String,String>,
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
			omitnames :Vec::new(),
			parsenames : Vec::new(),
			kmap : HashMap::new(),
			komitinitfns :HashMap::new(),
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

	pub fn set_init_func(&mut self, n :&str ,initfn :&str) {
		self.omitnames.push(format!("{}",n));
		self.komitinitfns.insert(format!("{}",n),format!("{}",initfn));
		return;
	}

	fn format_init_asn1(&self,tab :i32) -> String {
		let mut rets :String = "".to_string();
		asn1_gen_log_trace!("parsenames {:?}",self.parsenames);
		rets.push_str(&format_tab_line(tab , "fn init_asn1() -> Self {"));
		rets.push_str(&format_tab_line(tab + 1, &format!("{} {{",self.sname)));
		for k in self.parsenames.iter() {
			let v = self.kmap.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2, &format!("{} : {}::init_asn1(),", k,extract_type_name(v))));
		}
		for k in self.omitnames.iter() {
			let v = self.komitinitfns.get(k).unwrap();
			rets.push_str(&format_tab_line(tab + 2,&format!("{} : {}(),",k,v)));
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
/// ```rust
/// use asn1obj_codegen::{asn1_sequence,asn1_ext};
/// use asn1obj::{asn1obj_error_class,asn1obj_new_error};
/// use asn1obj::base::*;
/// use asn1obj::complex::*;
/// use asn1obj::asn1impl::Asn1Op;
///  use asn1obj::strop::asn1_format_line;
/// 
/// use num_bigint::{BigUint};
/// use hex::FromHex;
/// use std::error::Error;
/// use std::io::Write;
/// use serde_json;
/// 
/// #[asn1_sequence()]
/// #[derive(Clone)]
/// pub struct Asn1RsaPubkeyElem {
/// 	#[asn1_ext(initfn=c_default)]
/// 	pub c :Asn1BigNum,
/// 	pub n :Asn1BigNum,
/// 	pub e :Asn1BigNum,
/// }
/// 
/// fn c_default() -> Asn1BigNum {
/// 	Asn1BigNum::init_asn1()
/// }
/// 
/// #[asn1_sequence()]
/// #[derive(Clone)]
/// pub struct Asn1RsaPubkey {
/// 	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
/// }
/// 
/// fn format_vecs(buf :&[u8], tab :i32) -> String {
/// 	let mut outs :String = "".to_string();
/// 	let mut lasti : usize = 0;
/// 	let mut ki :usize;
/// 	for i in 0..buf.len() {
/// 		if (i%16) == 0 {
/// 			if i > 0 {
/// 				outs.push_str("    ");
/// 				while lasti != i {
/// 					if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
/// 						outs.push(buf[lasti] as char);
/// 					} else {
/// 						outs.push_str(".");
/// 					}
/// 					lasti += 1;
/// 				}
/// 				outs.push_str("\n");
/// 			}
/// 
/// 			for _j in 0..tab {
/// 				outs.push_str("    ");
/// 			}
/// 		}
/// 		if (i % 16) == 0 {
/// 			outs.push_str(&format!("{:02x}", buf[i]));	
/// 		} else {
/// 			outs.push_str(&format!(":{:02x}", buf[i]));	
/// 		}
/// 		
/// 	}
/// 
/// 	if lasti != buf.len() {
/// 		ki = buf.len();
/// 		while (ki % 16) != 0 {
/// 			outs.push_str("   ");
/// 			ki += 1;
/// 		}
/// 		outs.push_str("    ");
/// 		while lasti != buf.len() {
/// 			if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
/// 				outs.push(buf[lasti] as char);
/// 			} else {
/// 				outs.push_str(".");
/// 			}
/// 			lasti += 1;
/// 		}
/// 	}
/// 	outs.push_str("\n");
/// 	return outs;
/// }
/// 
/// 
/// fn main() -> Result<(),Box<dyn Error>> {
/// 	let mut pubkey :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
/// 	let mut pubkeyelem :Asn1RsaPubkeyElem = Asn1RsaPubkeyElem::init_asn1();
/// 	let nv :Vec<u8> = Vec::from_hex("df45f6d9925fe470dcb55c26afe0dfd6a0307cf9287342749b7341b342f87fa2b5238245ac73788b0016015834c59fd0481cb9cb97f575f13abd600799b3a2113ec2e4c22385fd45674326ffc55fa84ab2088063f48e8efeb7dd473194a079fabd96d4f59f70ccc0bb78628bc89725519cd57a180e54fd6608ef2d401124ed5e23598329eb13e2dd0ebdd7692bff9a07ce57ec50b1b3bc6d585d2585f96fc9276ed2d36b834420bd1b96f7a4e2b913795fe8744a2046ba537b18104ee98a8b7b959e009742091814211b15c6a5992f46c5a74b9398a47b01d20fc35228f174c617ca3ab2e89944147150c24c7619db1666bf0d447630683dea078274d8d3069d")?;
/// 	let ne :Vec<u8> = Vec::from_hex("010001")?;
/// 	pubkeyelem.n.val = BigUint::from_bytes_be(&nv);
/// 	pubkeyelem.e.val = BigUint::from_bytes_be(&ne);
/// 	pubkey.elem.val.push(pubkeyelem);
/// 	let outd = pubkey.encode_asn1()?;
/// 	let s = format_vecs(&outd,1);
/// 	let mut outs :String = "".to_string();
/// 	let mut outf = std::io::stdout();
/// 	outs.push_str("outs\n");
/// 	outs.push_str(&s);
/// 	std::io::stdout().write(outs.as_bytes())?;
/// 	pubkey.print_asn1("Rsa Public Key",0,&mut outf)?;
/// 	Ok(())
/// }
/// /*
/// output:
/// outs
///     30:82:01:0a:02:82:01:01:00:df:45:f6:d9:92:5f:e4    0.........E..._.
///     70:dc:b5:5c:26:af:e0:df:d6:a0:30:7c:f9:28:73:42    p..\&.....0|.(sB
///     74:9b:73:41:b3:42:f8:7f:a2:b5:23:82:45:ac:73:78    t.sA.B....#.E.sx
///     8b:00:16:01:58:34:c5:9f:d0:48:1c:b9:cb:97:f5:75    ....X4...H.....u
///     f1:3a:bd:60:07:99:b3:a2:11:3e:c2:e4:c2:23:85:fd    .:.`.....>...#..
///     45:67:43:26:ff:c5:5f:a8:4a:b2:08:80:63:f4:8e:8e    EgC&.._.J...c...
///     fe:b7:dd:47:31:94:a0:79:fa:bd:96:d4:f5:9f:70:cc    ...G1..y......p.
///     c0:bb:78:62:8b:c8:97:25:51:9c:d5:7a:18:0e:54:fd    ..xb...%Q..z..T.
///     66:08:ef:2d:40:11:24:ed:5e:23:59:83:29:eb:13:e2    f..-@.$.^#Y.)...
///     dd:0e:bd:d7:69:2b:ff:9a:07:ce:57:ec:50:b1:b3:bc    ....i+....W.P...
///     6d:58:5d:25:85:f9:6f:c9:27:6e:d2:d3:6b:83:44:20    mX]%..o.'n..k.D 
///     bd:1b:96:f7:a4:e2:b9:13:79:5f:e8:74:4a:20:46:ba    ........y_.tJ F.
///     53:7b:18:10:4e:e9:8a:8b:7b:95:9e:00:97:42:09:18    S{..N...{....B..
///     14:21:1b:15:c6:a5:99:2f:46:c5:a7:4b:93:98:a4:7b    .!...../F..K...{
///     01:d2:0f:c3:52:28:f1:74:c6:17:ca:3a:b2:e8:99:44    ....R(.t...:...D
///     14:71:50:c2:4c:76:19:db:16:66:bf:0d:44:76:30:68    .qP.Lv...f..Dv0h
///     3d:ea:07:82:74:d8:d3:06:9d:02:03:01:00:01          =...t.........
/// Rsa Public Key[0] Asn1RsaPubkeyElem
///     n: ASN1_BIGNUM
///         df:45:f6:d9:92:5f:e4:70:dc:b5:5c:26:af:e0:df:d6    .E..._.p..\&....
///         a0:30:7c:f9:28:73:42:74:9b:73:41:b3:42:f8:7f:a2    .0|.(sBt.sA.B...
///         b5:23:82:45:ac:73:78:8b:00:16:01:58:34:c5:9f:d0    .#.E.sx....X4...
///         48:1c:b9:cb:97:f5:75:f1:3a:bd:60:07:99:b3:a2:11    H.....u.:.`.....
///         3e:c2:e4:c2:23:85:fd:45:67:43:26:ff:c5:5f:a8:4a    >...#..EgC&.._.J
///         b2:08:80:63:f4:8e:8e:fe:b7:dd:47:31:94:a0:79:fa    ...c......G1..y.
///         bd:96:d4:f5:9f:70:cc:c0:bb:78:62:8b:c8:97:25:51    .....p...xb...%Q
///         9c:d5:7a:18:0e:54:fd:66:08:ef:2d:40:11:24:ed:5e    ..z..T.f..-@.$.^
///         23:59:83:29:eb:13:e2:dd:0e:bd:d7:69:2b:ff:9a:07    #Y.).......i+...
///         ce:57:ec:50:b1:b3:bc:6d:58:5d:25:85:f9:6f:c9:27    .W.P...mX]%..o.'
///         6e:d2:d3:6b:83:44:20:bd:1b:96:f7:a4:e2:b9:13:79    n..k.D ........y
///         5f:e8:74:4a:20:46:ba:53:7b:18:10:4e:e9:8a:8b:7b    _.tJ F.S{..N...{
///         95:9e:00:97:42:09:18:14:21:1b:15:c6:a5:99:2f:46    ....B...!...../F
///         c5:a7:4b:93:98:a4:7b:01:d2:0f:c3:52:28:f1:74:c6    ..K...{....R(.t.
///         17:ca:3a:b2:e8:99:44:14:71:50:c2:4c:76:19:db:16    ..:...D.qP.Lv...
///         66:bf:0d:44:76:30:68:3d:ea:07:82:74:d8:d3:06:9d    f..Dv0h=...t....
///     e: ASN1_BIGNUM 0x00010001
/// */
/// ```
///  internal expand will give
/// ```rust
/// #[asn1_sequence()]
/// #[derive(Clone)]
/// pub struct Asn1RsaPubkeyElem {
/// 	#[asn1_ext(initfn=c_default)]
/// 	pub c :Asn1BigNum,
/// 	pub n :Asn1BigNum,
/// 	pub e :Asn1BigNum,
/// }
/// 
/// fn c_default() -> Asn1BigNum {
/// 	Asn1BigNum::init_asn1()
/// }
/// 
/// #[asn1_sequence()]
/// #[derive(Clone)]
/// pub struct Asn1RsaPubkey {
/// 	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
/// }
/// 
/// ```
///  transfer into
/// ```rust
/// #[derive(Clone)] pub struct Asn1RsaPubkeyElem
/// { 
///     pub c : Asn1BigNum, 
///     pub n : Asn1BigNum, 
///     pub e : Asn1BigNum, 
/// }
/// asn1obj_error_class!{Asn1RsaPubkeyElemErrorCDrzpsmb4YFcGAwXvxP4}
/// 
/// impl Asn1Op for Asn1RsaPubkeyElem {
/// 
///     fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///         let mut mainv :serde_json::value::Value = serde_json::json!({});
///         let mut idx :i32 = 0;
///         
///         idx += self.n.encode_json("n",&mut mainv)?;
///         idx += self.e.encode_json("e",&mut mainv)?;
///         
///         if key.len() > 0 {
///             val[key] = mainv;
///         } else {
///             *val = mainv;
///         }
///         
///         return Ok(idx);
///     }
///     
///     fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///         let mainv :serde_json::value::Value;
///         let mut idx :i32=0;
///         
///         if key.len() > 0 {
///             let k = val.get(key);
///             if k.is_none() {
///                 self.n = Asn1BigNum::init_asn1();
///                 self.e = Asn1BigNum::init_asn1();
///                 return Ok(0);
///             }
///             mainv = serde_json::json!(k.clone());
///         } else {
///             mainv = val.clone();
///         }
///         
///         if !mainv.is_object() {
///             asn1obj_new_error!{Asn1RsaPubkeyElemErrorCDrzpsmb4YFcGAwXvxP4,"not object to decode"}
///         }
///         
///         idx += self.n.decode_json("n",&mainv)?;
///         idx += self.e.decode_json("e",&mainv)?;
///         
///         return Ok(idx);
///     }
///     
///     fn init_asn1() -> Self {
///         Asn1RsaPubkeyElem {
///             n : Asn1BigNum::init_asn1(),
///             e : Asn1BigNum::init_asn1(),
///             c : c_default(),
///         }
///     }
///     
///     fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///         let mut retv :usize = 0;
///         let mut _endsize :usize = code.len();
///         
///         let ro = self.n.decode_asn1(&code[retv.._endsize]);
///         if ro.is_err() {
///             let e = ro.err().unwrap();
///             return Err(e);
///         }
///         retv += ro.unwrap();
///         
///         let ro = self.e.decode_asn1(&code[retv.._endsize]);
///         if ro.is_err() {
///             let e = ro.err().unwrap();
///             return Err(e);
///         }
///         retv += ro.unwrap();
///         
///         Ok(retv)
///         
///     }
///     
///     fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///         let mut _v8 :Vec<u8> = Vec::new();
///         let mut encv :Vec<u8>;
///         
///         encv = self.n.encode_asn1()?;
///         for i in 0..encv.len() {
///             _v8.push(encv[i]);
///         }
///         
///         encv = self.e.encode_asn1()?;
///         for i in 0..encv.len() {
///             _v8.push(encv[i]);
///         }
///         
///         Ok(_v8)
///         
///     }
///     
///     fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///         let mut s :String;
///         s = asn1_format_line(tab,&format!("{} Asn1RsaPubkeyElem", name));
///         iowriter.write(s.as_bytes())?;
///         
///         s = format!("n");
///         self.n.print_asn1(&s,tab + 1, iowriter)?;
///         
///         s = format!("e");
///         self.e.print_asn1(&s,tab + 1, iowriter)?;
///         
///         Ok(())
///         
///     }
///     
/// }
/// 
/// #[derive(Clone)] pub struct Asn1RsaPubkey
/// { 
///     pub elem : Asn1Seq < Asn1RsaPubkeyElem > , 
/// }
/// asn1obj_error_class!{Asn1RsaPubkeyErrorGWvcOeiW8Tlueso6BX95}
/// 
/// impl Asn1Op for Asn1RsaPubkey {
///     
///     fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///         return self.elem.encode_json(key,val);
///     }
///     
///     fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
///         return self.elem.decode_json(key,val);
///     }
///     
///     fn init_asn1() -> Self {
///         Asn1RsaPubkey {
///             elem : Asn1Seq::init_asn1(),
///         }
///     }
///     
///     fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
///         let mut retv :usize = 0;
///         let mut _endsize :usize = code.len();
///         
///         let ro = self.elem.decode_asn1(&code[retv.._endsize]);
///         if ro.is_err() {
///             let e = ro.err().unwrap();
///             return Err(e);
///         }
///         retv += ro.unwrap();
///         
///         Ok(retv)
///         
///     }
///     
///     fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
///         let mut _v8 :Vec<u8> = Vec::new();
///         let encv :Vec<u8>;
///         
///         encv = self.elem.encode_asn1()?;
///         for i in 0..encv.len() {
///             _v8.push(encv[i]);
///         }
///         
///         Ok(_v8)
///         
///     }
///     
///     fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
///         return self.elem.print_asn1(name,tab,iowriter);
///     }
///     
/// }
/// 
/// ```
#[proc_macro_attribute]
pub fn asn1_sequence(_attr :TokenStream,item :TokenStream) -> TokenStream {
	//asn1_gen_log_trace!("item\n{}\n_attr\n{}",item.to_string(),_attr.to_string());
	let mut co :syn::DeriveInput;
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

	for a in &co.attrs {
		asn1_gen_log_trace!("path [{}]",a.path.get_ident().unwrap().to_string());
	}


	match co.data {
		syn::Data::Struct(ref mut _vv) => {
			match _vv.fields {
				syn::Fields::Named(ref mut _n) => {
					for _v in _n.named.iter_mut() {
						let mut callfn :Option<String> = None;
						let mut omitname :Option<String> = None;
						let n :String;
						let tn :String;
						let res = get_name_type(_v.clone());
						if res.is_err() {
							asn1_syn_error_fmt!("{:?}",res.err().unwrap());
						}
						(n,tn) = res.unwrap();
						asn1_gen_log_trace!("[{}]=[{}]",n,tn);
						let mut removed :Vec<usize> = vec![];
						let mut idx:usize = 0;
						while idx < _v.attrs.len() {
							let _a = &_v.attrs[idx];

							let v = format!("{}",_a.path.get_ident().unwrap().to_string());
							if v == ASN1_EXTMACRO {
								removed.push(idx);
								asn1_gen_log_trace!("[{}]=[{}][{}]",n,_a.path.get_ident().unwrap().to_string(),_a.tokens.to_string());

								let ntoks =proc_macro::TokenStream::from(_a.tokens.clone());
								let kv :SynKV = syn::parse_macro_input!(ntoks as SynKV);
								let oinitfn = kv.get_value(ASN1_INITFN);
								if oinitfn.is_some() {
									omitname = Some(format!("{}",n));
									callfn = Some(format!("{}",oinitfn.unwrap()));
								}
							}
							idx += 1;
						}
						if callfn.is_none() {
							asn1_gen_log_trace!("callfn.is_none");	
						} else {
							asn1_gen_log_trace!("callfn [{}]",callfn.as_ref().unwrap());
						}

						if callfn.is_none() && n.len() > 0 && tn.len() > 0 {
							asn1_gen_log_trace!("set name [{}]=[{}]",n,tn);
							cs.set_name(&n,&tn);
						} else if callfn.is_some() && omitname.is_some() {
							asn1_gen_log_trace!("n[{}]=[{}]",omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
							cs.set_init_func(omitname.as_ref().unwrap(),callfn.as_ref().unwrap());
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
    let ntok  = co.to_token_stream();
    let mut cc = ntok.to_string();
    cc.push_str("\n");
    cc.push_str(&(cs.format_asn1_code().unwrap()));
    asn1_gen_log_trace!("CODE\n{}",cc);
    cc.parse().unwrap()
}
