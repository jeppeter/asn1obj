use lazy_static::lazy_static;
use crate::logger::{_asn1_gen_get_environ_var};

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

pub (crate) fn asn1_gen_debug_level() -> i32 {
	return ASN1_GEN_PROC_VAR.debuglevel;
}
