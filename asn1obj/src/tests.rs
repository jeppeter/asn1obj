
use crate::base::{Asn1Integer};
use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out};
use crate::asn1impl::{Asn1Op};



#[test]
fn test_a001() {
	let mut a1 :Asn1Integer = Asn1Integer::init_asn1();
	a1.val = -2;
	let c = a1.encode_asn1().unwrap();
	asn1obj_log_trace!("format {:?}", c);
	return ;
}