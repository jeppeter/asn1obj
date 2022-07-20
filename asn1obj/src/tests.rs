
use crate::base::{Asn1Integer,Asn1Boolean,Asn1BitString,Asn1OctString,Asn1Null,Asn1Object,Asn1Enumerated,Asn1String,Asn1ImpInteger,Asn1ImpObject};
use crate::complex::{Asn1Opt,Asn1SetOf};
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

#[test]
fn test_a006() {
	let mut a1 :Asn1Object = Asn1Object::init_asn1();
	let mut v1 :Vec<u8>;
	let _ = a1.set_value("1.2.3.522.332").unwrap();
	v1 = vec![0x06,0x06,0x2a,0x03,0x84,0x0a,0x82,0x4c];
	let c = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
	assert!(a1.get_value() == "1.2.3.522.332");
	let _ = a1.set_value("1.2.3.522.332.222.2221.1111111111111111.2222.222222222222222222222222222222222222222222222222222222222.222222222222000000000000000000000000000000000003333333333333333333333333333333999999999999999999999992222222222222222.22222222222222222222222222222222222222222222333333333333333333333333333444444444444444444444").unwrap();
	v1 = vec![0x06,0x81,0x93,0x2a,0x03,0x84,0x0a,0x82,0x4c,0x81,0x5e,0x91,0x2d,0x81,0xfc,0xd1
,0xcb,0xb8,0xd5,0xe3,0x47,0x91,0x2e,0xa4,0xa0,0x9b,0xdb,0xa7,0xcb,0xb2,0xa6,0x8f
,0xf7,0x8d,0xdd,0xda,0x83,0xdd,0xbd,0xfb,0x8f,0xd7,0xc7,0x8e,0x9c,0xb8,0xf1,0xe3
,0xc7,0x0e,0x82,0xe8,0xf9,0xe9,0x8e,0x9c,0xc4,0x9d,0x8d,0xa6,0xd6,0x93,0xff,0xef
,0xc6,0xa9,0xc7,0x94,0x9a,0xae,0xf7,0xb9,0xd8,0xec,0xca,0xb2,0x81,0xea,0xe3,0xc7
,0xc4,0xed,0x81,0xa2,0xf7,0x9f,0xb8,0xa0,0xe8,0xba,0xf1,0xe8,0xd6,0xb5,0xf6,0xa5
,0x85,0xea,0x93,0xfb,0xa4,0xef,0xf3,0xa7,0xc7,0x0e,0x85,0xba,0x97,0xa8,0xee,0xe4
,0x8c,0xc8,0xe0,0xdd,0xa2,0xf6,0xf9,0x9b,0xe9,0x92,0xd1,0xf0,0xa3,0xd1,0xda,0xdc
,0x87,0xb0,0xb9,0xa6,0x91,0xd2,0x85,0x91,0xc9,0xd2,0xc7,0xdd,0x87,0xbe,0xe4,0x93
,0x86,0xa6,0xf0,0xc7,0x8e,0x1c];
	let c = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
	assert!(a1.get_value() == "1.2.3.522.332.222.2221.1111111111111111.2222.222222222222222222222222222222222222222222222222222222222.222222222222000000000000000000000000000000000003333333333333333333333333333333999999999999999999999992222222222222222.22222222222222222222222222222222222222222222333333333333333333333333333444444444444444444444");
}


#[test]
fn test_a007() {
	let mut a1 :Asn1Enumerated = Asn1Enumerated::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = -52224;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x0a,0x03,0xff,0x34,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -52224);
	assert!(s == v1.len());

	a1.val = -256;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x2,0xff,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -256);
	assert!(s == 4);


	a1.val = -255;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x2,0xff,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -255);
	assert!(s == 4);


	a1.val = -128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x1,0x80];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -128);
	assert!(s == 3);

	a1.val = -127;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x1,0x81];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -127);
	assert!(s == 3);


	a1.val = -129;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x2,0xff,0x7f];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -129);
	assert!(s == 4);


	a1.val = 128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x2,0x00,0x80];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 128);
	assert!(s == 4);


	a1.val = 65535;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x3,0x00,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 65535);
	assert!(s == 5);


	a1.val = 32768;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x3,0x00,0x80,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 32768);
	assert!(s == 5);


	a1.val = 32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x2,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 32767);
	assert!(s == 4);


	a1.val = -32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x2,0x80,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -32767);
	assert!(s == 4);


	a1.val = -32769;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x3,0xff,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -32769);
	assert!(s == 5);


	a1.val = -65537;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x3,0xfe,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -65537);
	assert!(s == 5);


	a1.val = -16777216;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x4,0xff,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -16777216);
	assert!(s == 6);


	a1.val = -16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x4,0xfe,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -16777217);
	assert!(s == 6);


	a1.val = 16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x4,0x01,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 16777217);
	assert!(s == 6);


	a1.val = -8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x3,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -8388608);
	assert!(s == 5);


	a1.val = 8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x4,0x00,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 8388608);
	assert!(s == 6);


	a1.val = -2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x4,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -2147483648);
	assert!(s == 6);


	a1.val = 2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x5,0x00,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 2147483648);
	assert!(s == 7);


	a1.val = 2147483649;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x5,0x00,0x80,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 2147483649);
	assert!(s == 7);

	a1.val = 4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x5,0x01,0x00,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 4294967297);
	assert!(s == 7);

	a1.val = -4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0xa,0x5,0xfe,0xff,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -4294967297);
	assert!(s == 7);

	return ;
}

#[test]
fn test_a008() {
	let mut a1 :Asn1String = Asn1String::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = "helloworldt".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x0c,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworldt");
	assert!(s == v1.len());

	a1.val = "helloworlds".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x0c,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x73];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworlds");
	assert!(s == v1.len());

	a1.val = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x0c,0x81,0x80,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74,0x40,0x40,
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
fn test_a009() {
	let mut a1 :Asn1Opt<Asn1Integer> = Asn1Opt::init_asn1();
	let mut c :Asn1Integer = Asn1Integer::init_asn1();
	c.val = -2;
	a1.val = Some(c.clone());
	let c1 = a1.encode_asn1().unwrap();
	let mut v1 :Vec<u8>;
	v1 = vec![0x2,0x1,0xfe];
	assert!(check_equal_u8(&v1,&c1));
	v1 = vec![0x5,0x1,0xfe];
	let c1 = a1.decode_asn1(&v1).unwrap();
	assert!(c1 == 0);
	assert!(a1.val.is_none());

	a1.val = None;
	let c1 = a1.encode_asn1().unwrap();
	v1 = vec![];
	assert!(check_equal_u8(&v1,&c1));

}

#[test]
fn test_a010() {
	let mut a1 :Asn1SetOf<Asn1Integer> = Asn1SetOf::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Integer = Asn1Integer::init_asn1();
	let _ = a1.set_tag(0x3);
	n1.val = -20;
	a1.val.push(n1.clone());
	n1.val = 30;
	a1.val.push(n1.clone());
	n1.val = 50;
	a1.val.push(n1.clone());
	v1 = vec![0xa3,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	v1 = vec![0xa3,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.get_tag() == 0x3);
	assert!(a1.val.len() == 3);
	assert!(a1.val[0].val == -20);
	assert!(a1.val[1].val == 30);
	assert!(a1.val[2].val == 50);
}

#[test]
fn test_a011() {
	let mut a1 :Asn1ImpInteger = Asn1ImpInteger::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = -2;
	let _ = a1.set_tag(0x1).unwrap();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x81,0x1,0xfe];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -2);
	assert!(a1.get_tag() == 0x1);
	assert!(s == 3);

	a1.val = -256;
	let _ = a1.set_tag(0x2).unwrap();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0xff,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -256);
	assert!(a1.get_tag() == 0x2);
	assert!(s == 4);


	a1.val = -255;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0xff,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -255);
	assert!(s == 4);


	a1.val = -128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x1,0x80];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -128);
	assert!(s == 3);

	a1.val = -127;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x1,0x81];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -127);
	assert!(s == 3);


	a1.val = -129;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0xff,0x7f];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -129);
	assert!(s == 4);


	a1.val = 128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0x00,0x80];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 128);
	assert!(s == 4);


	a1.val = 65535;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0x00,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 65535);
	assert!(s == 5);


	a1.val = 32768;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0x00,0x80,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 32768);
	assert!(s == 5);


	a1.val = 32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 32767);
	assert!(s == 4);


	a1.val = -32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0x80,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -32767);
	assert!(s == 4);


	a1.val = -32769;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0xff,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -32769);
	assert!(s == 5);


	a1.val = -65537;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0xfe,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -65537);
	assert!(s == 5);


	a1.val = -16777216;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0xff,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -16777216);
	assert!(s == 6);


	a1.val = -16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0xfe,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -16777217);
	assert!(s == 6);


	a1.val = 16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0x01,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 16777217);
	assert!(s == 6);


	a1.val = -8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -8388608);
	assert!(s == 5);


	a1.val = 8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0x00,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 8388608);
	assert!(s == 6);


	a1.val = -2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -2147483648);
	assert!(s == 6);


	a1.val = 2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0x00,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 2147483648);
	assert!(s == 7);


	a1.val = 2147483649;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0x00,0x80,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 2147483649);
	assert!(s == 7);

	a1.val = 4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0x01,0x00,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == 4294967297);
	assert!(s == 7);

	a1.val = -4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0xfe,0xff,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == -4294967297);
	assert!(s == 7);

	return ;
}


#[test]
fn test_a012() {
	let mut a1 :Asn1ImpObject = Asn1ImpObject::init_asn1();
	let mut v1 :Vec<u8>;
	let _ = a1.set_value("1.2.3.522.332").unwrap();
	let _ = a1.set_tag(0x2).unwrap();
	v1 = vec![0x82,0x06,0x2a,0x03,0x84,0x0a,0x82,0x4c];
	let c = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
	assert!(a1.get_value() == "1.2.3.522.332");
	let _ = a1.set_value("1.2.3.522.332.222.2221.1111111111111111.2222.222222222222222222222222222222222222222222222222222222222.222222222222000000000000000000000000000000000003333333333333333333333333333333999999999999999999999992222222222222222.22222222222222222222222222222222222222222222333333333333333333333333333444444444444444444444").unwrap();
	v1 = vec![0x82,0x81,0x93,0x2a,0x03,0x84,0x0a,0x82,0x4c,0x81,0x5e,0x91,0x2d,0x81,0xfc,0xd1
,0xcb,0xb8,0xd5,0xe3,0x47,0x91,0x2e,0xa4,0xa0,0x9b,0xdb,0xa7,0xcb,0xb2,0xa6,0x8f
,0xf7,0x8d,0xdd,0xda,0x83,0xdd,0xbd,0xfb,0x8f,0xd7,0xc7,0x8e,0x9c,0xb8,0xf1,0xe3
,0xc7,0x0e,0x82,0xe8,0xf9,0xe9,0x8e,0x9c,0xc4,0x9d,0x8d,0xa6,0xd6,0x93,0xff,0xef
,0xc6,0xa9,0xc7,0x94,0x9a,0xae,0xf7,0xb9,0xd8,0xec,0xca,0xb2,0x81,0xea,0xe3,0xc7
,0xc4,0xed,0x81,0xa2,0xf7,0x9f,0xb8,0xa0,0xe8,0xba,0xf1,0xe8,0xd6,0xb5,0xf6,0xa5
,0x85,0xea,0x93,0xfb,0xa4,0xef,0xf3,0xa7,0xc7,0x0e,0x85,0xba,0x97,0xa8,0xee,0xe4
,0x8c,0xc8,0xe0,0xdd,0xa2,0xf6,0xf9,0x9b,0xe9,0x92,0xd1,0xf0,0xa3,0xd1,0xda,0xdc
,0x87,0xb0,0xb9,0xa6,0x91,0xd2,0x85,0x91,0xc9,0xd2,0xc7,0xdd,0x87,0xbe,0xe4,0x93
,0x86,0xa6,0xf0,0xc7,0x8e,0x1c];
	let c = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
	assert!(a1.get_value() == "1.2.3.522.332.222.2221.1111111111111111.2222.222222222222222222222222222222222222222222222222222222222.222222222222000000000000000000000000000000000003333333333333333333333333333333999999999999999999999992222222222222222.22222222222222222222222222222222222222222222333333333333333333333333333444444444444444444444");
}