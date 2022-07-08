
use std::env;
use std::io::{Write};
use std::fs;
//use std::io::prelude::*;
use lazy_static::lazy_static;



fn _asn1_get_environ_var(envname :&str) -> String {
	match env::var(envname) {
		Ok(v) => {
			format!("{}",v)
		},
		Err(_e) => {
			String::from("")
		}
	}
}

struct LogVar {
	level :i32,
	nostderr : bool,
	wfile : Option<fs::File>,
}


fn asn1_proc_log_init(prefix :&str) -> LogVar {
	let mut getv :String;
	let mut retv :i32 = 0;
	let mut nostderr :bool = false;
	let mut coptfile :Option<fs::File> = None;
	let mut key :String;

	key = format!("{}_LEVEL", prefix);
	getv = _asn1_get_environ_var(&key);
	if getv.len() > 0 {
		match getv.parse::<i32>() {
			Ok(v) => {
				retv = v;
			},
			Err(e) => {
				retv = 0;
				eprintln!("can not parse [{}] error[{}]", getv,e);
			}
		}
	}

	key = format!("{}_NOSTDERR",prefix);
	getv = _asn1_get_environ_var(&key);
	if getv.len() > 0 {
		nostderr = true;
	}



	key = format!("{}_LOGFILE",prefix);
	getv = _asn1_get_environ_var(&key);
	if getv.len() > 0 {
		let fo = fs::File::create(&getv);
		if fo.is_err() {
			eprintln!("can not open [{}]", getv);
		} else {
			coptfile = Some(fo.unwrap());
		}
	}

	return LogVar {
		level : retv,
		nostderr : nostderr,
		wfile : coptfile,		
	};
}


lazy_static! {
	static ref ASN1_OBJ_LOG_LEVEL : LogVar = {
		asn1_proc_log_init("ASN1OBJ")
	};
}


pub (crate)  fn asn1obj_debug_out(level :i32, outs :String) {
	if ASN1_OBJ_LOG_LEVEL.level >= level {
		eprintln!("will out");
		if !ASN1_OBJ_LOG_LEVEL.nostderr {
			eprintln!("{}", outs);
		}

		if ASN1_OBJ_LOG_LEVEL.wfile.is_some() {
			let mut wf = ASN1_OBJ_LOG_LEVEL.wfile.as_ref().unwrap();
			let _ = wf.write(outs.as_bytes());
			let _ = wf.write(b"\n");
		}
	}
	return;
}


#[macro_export]
macro_rules! asn1obj_log_error {
	($($arg:tt)+) => {
		let mut c :String= format!("[{}:{}] <ERROR> ",file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		asn1obj_debug_out(0, c);
	}
}

#[macro_export]
macro_rules! asn1obj_log_warn {
	($($arg:tt)+) => {
		let mut c :String= format!("[{}:{}] <WARN> ",file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		asn1obj_debug_out(10, c);
	}
}


#[macro_export]
macro_rules! asn1obj_log_info {
	($($arg:tt)+) => {
		let mut c :String= format!("[{}:{}] <INFO> ",file!(),line!());
		c.push_str(&(format!($($arg)+)[..]));
		asn1obj_debug_out(20, c);
	}
}

#[macro_export]
macro_rules! asn1obj_log_trace {
	($($arg:tt)+) => {
		let mut _c :String= format!("[{}:{}] <TRACE> ",file!(),line!());
		_c.push_str(&(format!($($arg)+)[..]));
		asn1obj_debug_out(40, _c);
	}
}


#[macro_export]
macro_rules! asn1obj_assert {
	($v:expr , $($arg:tt)+) => {
		if !($v) {
			let mut _c :String= format!("[{}:{}] ",file!(),line!());
			_c.push_str(&(format!($($arg)+)[..]));
			panic!("{}", _c);
		}
	}
}