
asn1_gen_error_class!{Asn1ExtError}

fn _get_synkv(ntoks :proc_macro::TokenStream) -> Result<SynKV,Box<dyn Error>> {
	let ores = syn::parse::<SynKV>(ntoks);
	if ores.is_err() {
		asn1_gen_new_error!{Asn1ExtError,"not parse synkv"}
	}
	Ok(ores.unwrap())
}

fn filter_attrib(_v :&mut syn::Field) -> Result<(String,String,SynKV),Box<dyn Error>> {
	let mut retv :SynKV = SynKV::new();
	let n :String;
	let tn :String;
	let res = get_name_type(_v.clone());
	if res.is_err() {
		asn1_gen_new_error!{Asn1ExtError,"{:?}",res.err().unwrap()}
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
			let kv :SynKV = _get_synkv(ntoks)?;
			for k in kv.get_keys().iter() {
				let ov = kv.get_value(k).unwrap();
				retv.set_attr(k,&ov).unwrap();
			}
		}
		idx += 1;
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

	return Ok((n,tn,retv));
}