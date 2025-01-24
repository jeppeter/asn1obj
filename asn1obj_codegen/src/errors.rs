
macro_rules! asn1_gen_error_class {
	($type:ident) => {
	#[derive(Debug,Clone)]
	struct $type {
		msg :String,		
	}

	impl $type {
		fn create(c :&str) -> $type {
			$type {msg : format!("{}",c)}
		}
	}

	impl std::fmt::Display for $type {
		fn fmt(&self,f :&mut std::fmt::Formatter) -> std::fmt::Result {
			write!(f,"{}",self.msg)
		}
	}

	impl std::error::Error for $type {}
	};
}

macro_rules! asn1_gen_new_error {
	($type:ty,$($a:expr),*) => {
		{
		let mut c :String= format!("[{}:{}][{}]",file!(),line!(),stringify!($type));
		c.push_str(&(format!($($a),*)[..]));
		return Err(Box::new(<$type>::create(c.as_str())));
	  }
	};
}

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
