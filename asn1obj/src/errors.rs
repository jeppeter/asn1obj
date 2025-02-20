#[macro_export]
macro_rules! asn1obj_error_class {
	($type:ident) => {
	#[derive(Debug,Clone)]
	pub struct $type {
		msg :String,		
	}

	#[allow(dead_code)]
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

#[macro_export]
macro_rules! asn1obj_new_error {
	($type:ty,$($a:expr),*) => {
		{
		let mut c :String= format!("[{}:{}][{}]",file!(),line!(),stringify!($type));
		c.push_str(&(format!($($a),*)[..]));
		return Err(Box::new(<$type>::create(c.as_str())));
	  }
	};
}