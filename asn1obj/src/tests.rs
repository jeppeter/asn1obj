
use crate::base::{Asn1Integer};
use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};
use crate::asn1impl::{Asn1Op};


fn check_equal_u8(a :&[u8],b :&[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}


	for i in 0..a.len() {
		if a[i] != b[i] {
			return false;
		}
	}
	return true;
}

#[test]
fn test_a001() {
	let mut a1 :Asn1Integer = Asn1Integer::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = -2;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x1,0xfe];
	assert!(check_equal_u8(&c,&v1));
	asn1obj_log_trace!("format {:?}", c);
	a1.val = -256;
	let c = a1.encode_asn1().unwrap();
	asn1obj_log_trace!("format {:?}", c);
	a1.val = -255;
	let c = a1.encode_asn1().unwrap();
	asn1obj_log_trace!("format {:?}", c);
	a1.val = -((1 << 16) - 1);
	let c = a1.encode_asn1().unwrap();
	asn1obj_log_trace!("format {:?}", c);
	a1.val = -((1 << 16) + 1);
	let c = a1.encode_asn1().unwrap();
	asn1obj_log_trace!("format {:?}", c);
	let mut v1 :Vec<u8>;
	v1 = vec![0x2,0x1,0xfe];
	let _ = a1.decode_asn1(&v1).unwrap();
	asn1obj_log_trace!("a1 val {}",a1.val);

	v1 = vec![0x2,0x2,0xff,0x0];
	let _ = a1.decode_asn1(&v1).unwrap();
	asn1obj_log_trace!("a1 val {}",a1.val);

	return ;
}