
use crate::base::{Asn1Integer,Asn1Boolean,Asn1BitString,Asn1OctString,Asn1Null};
use crate::{asn1obj_log_trace};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};
use crate::asn1impl::{Asn1Op};


fn check_equal_u8(a :&[u8],b :&[u8]) -> bool {
	if a.len() != b.len() {
		return false;
	}


	for i in 0..a.len() {
		if a[i] != b[i] {
			asn1obj_log_trace!("a [{}] [0x{:02x}] b[{}] [0x{:02x}]",i,a[i],i,b[i]);
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

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -2);
	assert!(s == 3);

	a1.val = -256;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x2,0xff,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -256);
	assert!(s == 4);


	a1.val = -255;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x2,0xff,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -255);
	assert!(s == 4);


	a1.val = -128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x1,0x80];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -128);
	assert!(s == 3);

	a1.val = -127;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x1,0x81];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -127);
	assert!(s == 3);


	a1.val = -129;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x2,0xff,0x7f];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -129);
	assert!(s == 4);


	a1.val = 128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x2,0x00,0x80];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 128);
	assert!(s == 4);


	a1.val = 65535;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x3,0x00,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 65535);
	assert!(s == 5);


	a1.val = 32768;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x3,0x00,0x80,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 32768);
	assert!(s == 5);


	a1.val = 32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x2,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 32767);
	assert!(s == 4);


	a1.val = -32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x2,0x80,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -32767);
	assert!(s == 4);


	a1.val = -32769;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x3,0xff,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -32769);
	assert!(s == 5);


	a1.val = -65537;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x3,0xfe,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -65537);
	assert!(s == 5);


	a1.val = -16777216;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x4,0xff,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -16777216);
	assert!(s == 6);


	a1.val = -16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x4,0xfe,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -16777217);
	assert!(s == 6);


	a1.val = 16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x4,0x01,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 16777217);
	assert!(s == 6);


	a1.val = -8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x3,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -8388608);
	assert!(s == 5);


	a1.val = 8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x4,0x00,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 8388608);
	assert!(s == 6);


	a1.val = -2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x4,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -2147483648);
	assert!(s == 6);


	a1.val = 2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x5,0x00,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 2147483648);
	assert!(s == 7);


	a1.val = 2147483649;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x5,0x00,0x80,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 2147483649);
	assert!(s == 7);

	a1.val = 4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x5,0x01,0x00,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 4294967297);
	assert!(s == 7);

	a1.val = -4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x2,0x5,0xfe,0xff,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -4294967297);
	assert!(s == 7);

	return ;
}

#[test]
fn test_a002() {
	let mut a1 :Asn1Boolean = Asn1Boolean::init_asn1();
	let mut v1 :Vec<u8>;

	a1.val = false;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x1,0x1,0x0];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == false);
	assert!(s == 3);

	a1.val = true;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x1,0x1,0xff];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == true);
	assert!(s == 3);
}

#[test]
fn test_a003() {
	let mut a1 :Asn1BitString = Asn1BitString::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = "helloworldt".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x3,0xc,0x2,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworldt");
	assert!(s == v1.len());

	a1.val = "helloworlds".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x3,0xc,0x0,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x73];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworlds");
	assert!(s == v1.len());

	a1.val = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x3,0x81,0x81,0x6,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
		,0x40,0x40,0x40,0x40,0x40];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	let cv = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
	asn1obj_log_trace!("val [{}]",a1.val);
	asn1obj_log_trace!("cv  [{}]",cv);
	assert!(a1.val == cv);
	assert!(s == v1.len());
}

#[test]
fn test_a004() {
	let mut a1 :Asn1OctString = Asn1OctString::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = "helloworldt".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x04,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworldt");
	assert!(s == v1.len());

	a1.val = "helloworlds".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x04,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x73];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworlds");
	assert!(s == v1.len());

	a1.val = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x04,0x81,0x80,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,
		0x40,0x40,0x40];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	let cv = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
	asn1obj_log_trace!("val [{}]",a1.val);
	asn1obj_log_trace!("cv  [{}]",cv);
	assert!(a1.val == cv);
	assert!(s == v1.len());
}

#[test]
fn test_a005() {
	let mut a1 :Asn1Null = Asn1Null::init_asn1();
	let v1 :Vec<u8>;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x05,0x00];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
}