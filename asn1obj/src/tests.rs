
//use asn1obj_codegen::{asn1_sequence};

use crate::base::*;
use crate::complex::{Asn1Opt,Asn1ImpSet,Asn1Seq,Asn1Set,Asn1Ndef,Asn1Imp};
#[allow(unused_imports)]
use crate::{asn1obj_log_trace,asn1obj_error_class,asn1obj_new_error,asn1obj_debug_buffer_trace,asn1obj_format_buffer_log};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};
use crate::asn1impl::{Asn1Op};
use crate::consts::*;
use chrono::{Utc,DateTime,Datelike,Timelike};
use chrono::prelude::*;

use num_bigint::{BigUint};
use num_traits::Num;


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
	let mut a1 :Asn1ImpSet<Asn1Integer,3> = Asn1ImpSet::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Integer = Asn1Integer::init_asn1();
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
	assert!(a1.val.len() == 3);
	assert!(a1.val[0].val == -20);
	assert!(a1.val[1].val == 30);
	assert!(a1.val[2].val == 50);
}

#[test]
fn test_a011() {
	let mut a1 :Asn1Imp<Asn1Integer,1> = Asn1Imp::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val.val = -2;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x81,0x1,0xfe];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -2);
	assert!(s == 3);

	let mut a1 :Asn1Imp<Asn1Integer,2> = Asn1Imp::init_asn1();
	a1.val.val = -256;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0xff,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -256);
	assert!(s == 4);


	a1.val.val = -255;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0xff,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -255);
	assert!(s == 4);


	a1.val.val = -128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x1,0x80];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -128);
	assert!(s == 3);

	a1.val.val = -127;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x1,0x81];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -127);
	assert!(s == 3);


	a1.val.val = -129;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0xff,0x7f];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -129);
	assert!(s == 4);


	a1.val.val = 128;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0x00,0x80];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 128);
	assert!(s == 4);


	a1.val.val = 65535;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0x00,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 65535);
	assert!(s == 5);


	a1.val.val = 32768;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0x00,0x80,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 32768);
	assert!(s == 5);


	a1.val.val = 32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 32767);
	assert!(s == 4);


	a1.val.val = -32767;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x2,0x80,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -32767);
	assert!(s == 4);


	a1.val.val = -32769;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0xff,0x7f,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -32769);
	assert!(s == 5);


	a1.val.val = -65537;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0xfe,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -65537);
	assert!(s == 5);


	a1.val.val = -16777216;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0xff,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -16777216);
	assert!(s == 6);


	a1.val.val = -16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0xfe,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -16777217);
	assert!(s == 6);


	a1.val.val = 16777217;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0x01,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 16777217);
	assert!(s == 6);


	a1.val.val = -8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x3,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -8388608);
	assert!(s == 5);


	a1.val.val = 8388608;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0x00,0x80,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 8388608);
	assert!(s == 6);


	a1.val.val = -2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x4,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));

	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -2147483648);
	assert!(s == 6);


	a1.val.val = 2147483648;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0x00,0x80,0x00,0x00,0x00];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 2147483648);
	assert!(s == 7);


	a1.val.val = 2147483649;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0x00,0x80,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 2147483649);
	assert!(s == 7);

	a1.val.val = 4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0x01,0x00,0x00,0x00,0x01];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == 4294967297);
	assert!(s == 7);

	a1.val.val = -4294967297;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x82,0x5,0xfe,0xff,0xff,0xff,0xff];
	assert!(check_equal_u8(&c,&v1));
	
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == -4294967297);
	assert!(s == 7);

	return ;
}


#[test]
fn test_a012() {
	let mut a1 :Asn1Imp<Asn1Object,2> = Asn1Imp::init_asn1();
	let mut v1 :Vec<u8>;
	let _ = a1.val.set_value("1.2.3.522.332").unwrap();
	v1 = vec![0x82,0x06,0x2a,0x03,0x84,0x0a,0x82,0x4c];
	let c = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
	assert!(a1.val.get_value() == "1.2.3.522.332");
	let _ = a1.val.set_value("1.2.3.522.332.222.2221.1111111111111111.2222.222222222222222222222222222222222222222222222222222222222.222222222222000000000000000000000000000000000003333333333333333333333333333333999999999999999999999992222222222222222.22222222222222222222222222222222222222222222333333333333333333333333333444444444444444444444").unwrap();
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
	assert!(a1.val.get_value() == "1.2.3.522.332.222.2221.1111111111111111.2222.222222222222222222222222222222222222222222222222222222222.222222222222000000000000000000000000000000000003333333333333333333333333333333999999999999999999999992222222222222222.22222222222222222222222222222222222222222222333333333333333333333333333444444444444444444444");
}

#[test]
fn test_a013() {
	let mut a1 :Asn1Imp<Asn1String,4> = Asn1Imp::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val.val = "helloworldt".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x84,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == "helloworldt");
	assert!(s == v1.len());

	a1.val.val = "helloworlds".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x84,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x73];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == "helloworlds");
	assert!(s == v1.len());

	a1.val.val = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x84,0x81,0x80,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74,0x40,0x40,
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
	asn1obj_log_trace!("val [{}]",a1.val.val);
	asn1obj_log_trace!("cv  [{}]",cv);
	assert!(a1.val.val == cv);
	assert!(s == v1.len());
}

#[test]
fn test_a014() {
	let mut a1 :Asn1Seq<Asn1Integer> = Asn1Seq::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Integer = Asn1Integer::init_asn1();
	n1.val = -20;
	a1.val.push(n1.clone());
	n1.val = 30;
	a1.val.push(n1.clone());
	n1.val = 50;
	a1.val.push(n1.clone());
	v1 = vec![0x30,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	v1 = vec![0x30,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.val.len() == 3);
	assert!(a1.val[0].val == -20);
	assert!(a1.val[1].val == 30);
	assert!(a1.val[2].val == 50);
}

#[test]
fn test_a015() {
	let mut a1 :Asn1Set<Asn1Integer> = Asn1Set::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Integer = Asn1Integer::init_asn1();
	n1.val = -20;
	a1.val.push(n1.clone());
	n1.val = 30;
	a1.val.push(n1.clone());
	n1.val = 50;
	a1.val.push(n1.clone());
	v1 = vec![0x31,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	v1 = vec![0x31,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.val.len() == 3);
	assert!(a1.val[0].val == -20);
	assert!(a1.val[1].val == 30);
	assert!(a1.val[2].val == 50);
}

#[test]
fn test_a016() {
	let mut a1 :Asn1ImpSet<Asn1Integer,4> = Asn1ImpSet::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Integer = Asn1Integer::init_asn1();
	n1.val = -20;
	a1.val.push(n1.clone());
	n1.val = 30;
	a1.val.push(n1.clone());
	n1.val = 50;
	a1.val.push(n1.clone());
	v1 = vec![0xa4,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	v1 = vec![0xa4,0x9,0x2,0x1,0xec,0x2,0x1,0x1e,0x2,0x1,0x32];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.val.len() == 3);
	assert!(a1.val[0].val == -20);
	assert!(a1.val[1].val == 30);
	assert!(a1.val[2].val == 50);
}

#[test]
fn test_a017() {
	let mut a1 :Asn1ImpSet<Asn1Set<Asn1Integer>,4> = Asn1ImpSet::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Set<Asn1Integer> = Asn1Set::init_asn1();
	let mut i1 :Asn1Integer = Asn1Integer::init_asn1();
	i1.val = -20;
	n1.val.push(i1.clone());
	a1.val.push(n1.clone());
	i1.val = 30;
	n1 = Asn1Set::init_asn1();	
	n1.val.push(i1.clone());
	a1.val.push(n1.clone());
	i1.val = 50;
	n1 = Asn1Set::init_asn1();	
	n1.val.push(i1.clone());
	a1.val.push(n1.clone());
	v1 = vec![0xa4,0xf,0x31,0x3,0x2,0x1,0xec,0x31,0x3,0x2,0x1,0x1e,0x31,0x3,0x2,0x1,0x32];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	v1 = vec![0xa4,0xf,0x31,0x3,0x2,0x1,0xec,0x31,0x3,0x2,0x1,0x1e,0x31,0x3,0x2,0x1,0x32];
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(s == v1.len());
	assert!(a1.val.len() == 3);
	assert!(a1.val[0].val[0].val == -20);
	assert!(a1.val[1].val[0].val == 30);
	assert!(a1.val[2].val[0].val == 50);
}

#[test]
fn test_a018() {
	let mut a1 :Asn1Ndef<Asn1String,4> = Asn1Ndef::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1String = Asn1String::init_asn1();
	v1 = vec![0xa4,0x2,0xc,0x0];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	n1.val = "helloworldt".to_string();
	a1.val = Some(n1.clone());
	v1 = vec![0xa4,0xd,0xc,0xb,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));

	let mut a1 :Asn1Ndef<Asn1Integer,4> = Asn1Ndef::init_asn1();
	let mut v1 :Vec<u8>;
	let mut n1 :Asn1Integer = Asn1Integer::init_asn1();
	v1 = vec![0xa4,0x3,0x2,0x1,0x0];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	n1.val = 20;
	a1.val = Some(n1.clone());
	v1 = vec![0xa4,0x3,0x2,0x1,0x14];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));

}

#[test]
fn test_a019() {
	let mut a1 :Asn1Any = Asn1Any::init_asn1();
	let v1 :Vec<u8>;
	v1 = vec![0x70,0x3,0x22,0x22,0x31];
	let v2 = vec![0x22,0x22,0x31];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.tag == 0x70);
	assert!(check_equal_u8(&a1.content,&v2));

	let v2 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&v2,&v1));
}


#[test]
fn test_a021() {
	let mut a1 :Asn1PrintableString = Asn1PrintableString::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val = "helloworldt".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x13,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworldt");
	assert!(s == v1.len());

	a1.val = "helloworlds".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x13,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x73];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworlds");
	assert!(a1.flag == 0x13);
	assert!(s == v1.len());

	a1.val = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x13,0x81,0x80,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74,0x40,0x40,
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

	a1.val = "helloworldt".to_string();
	a1.flag = 0x16;
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x16,0x0b,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val == "helloworldt");
	assert!(a1.flag == 0x16);
	assert!(s == v1.len());


}

#[test]
#[allow(deprecated)]
fn test_a022() {
	let mut a1 :Asn1Time = Asn1Time::init_asn1();
	let _ = a1.set_value_str("2022-02-02 01:20:33").unwrap();
	let c1 = a1.encode_asn1().unwrap();
	let mut v1 :Vec<u8>;
	v1 = vec![0x17,0xf,0x32,0x30,0x32,0x32,0x30,0x32,0x30,0x32,0x30,0x31,0x32,0x30,0x33,0x33,0x5a];
	assert!(check_equal_u8(&c1,&v1));
	v1 = vec![0x17,0x13,0x32,0x30,0x32,0x32,0x30,0x32,0x30,0x32,0x30,0x31,0x32,0x30,0x33,0x33,0x2b,0x31,0x30,0x30,0x30];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	asn1obj_log_trace!("value str {}", a1.get_value_str());
	assert!(a1.get_value_str() == "2022-02-01 15:20:33");
	v1 = vec![0x17,0xf,0x32,0x30,0x32,0x32,0x30,0x32,0x32,0x39,0x30,0x31,0x32,0x30,0x33,0x33,0x5a];
	let c1 = a1.decode_asn1(&v1);
	assert!(c1.is_err());
	assert!(a1.get_value_str() == "2022-02-01 15:20:33");
	let dt : DateTime<Utc> = a1.get_value_time().unwrap();
	assert!(dt.year() == 2022);
	assert!(dt.month() == 2);
	assert!(dt.day() == 1);
	assert!(dt.hour() == 15);
	assert!(dt.minute() == 20);
	assert!(dt.second() == 33);
	let dt : DateTime<Utc> = Utc.ymd(2021,7,8).and_hms(22,21,0);
	let _ = a1.set_value_time(&dt).unwrap();
	assert!(a1.get_value_str() == "2021-07-08 22:21:00");
	v1 = vec![0x17,0x0d,0x30,0x37,0x30,0x36,0x30,0x35,0x32,0x32,0x30,0x33,0x32,0x31,0x5a];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.get_value_str() == "2007-06-05 22:03:21");
	v1 = vec![0x17,0x0d,0x31,0x32,0x30,0x36,0x30,0x35,0x32,0x32,0x31,0x33,0x32,0x31,0x5a];
	let c = a1.decode_asn1(&v1).unwrap();
	assert!(c == v1.len());
	assert!(a1.get_value_str() == "2012-06-05 22:13:21");
	return;
}

#[test]
fn test_a023() {
	let mut a1 :Asn1BigNum = Asn1BigNum::init_asn1();
	a1.val = BigUint::from_str_radix("11223344556677889900aabbccddeeff",16).unwrap();
	let mut v1 :Vec<u8>;
	v1 = vec![0x2,0x10,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	let cb = a1.val.to_bytes_be();
	assert!(check_equal_u8(&cb,&v1[2..]));
	a1.val = BigUint::from_str_radix("ff223344556677889900aabbccddeeff",16).unwrap();
	v1 = vec![0x2,0x11,0x00,0xff,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,0xaa,0xbb,0xcc,0xdd,0xee,0xff];
	let c1 = a1.encode_asn1().unwrap();
	assert!(check_equal_u8(&c1,&v1));
	let cb = a1.val.to_bytes_be();
	assert!(check_equal_u8(&cb,&v1[3..]));
	let _ = a1.decode_asn1(&v1).unwrap();
	let cb :BigUint = BigUint::from_str_radix("ff223344556677889900aabbccddeeff",16).unwrap();
	assert!(cb == a1.val);
}

#[test]
fn test_a024() {
	let mut a1 :Asn1Imp<Asn1BitString,4> = Asn1Imp::init_asn1();
	let mut v1 :Vec<u8>;
	a1.val.val = "helloworldt".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x84,0xc,0x2,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == "helloworldt");
	assert!(s == v1.len());

	a1.val.val = "helloworlds".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x84,0xc,0x0,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x73];
	assert!(check_equal_u8(&v1,&c));
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(a1.val.val == "helloworlds");
	assert!(s == v1.len());

	a1.val.val = "helloworldt@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@".to_string();
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x84,0x81,0x81,0x6,0x68,0x65,0x6c,0x6c,0x6f,0x77,0x6f,0x72,0x6c,0x64,0x74,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40,0x40
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
	asn1obj_log_trace!("val [{}]",a1.val.val);
	asn1obj_log_trace!("cv  [{}]",cv);
	assert!(a1.val.val == cv);
	assert!(s == v1.len());
}


#[test]
fn test_a025() {
	let mut a1 :Asn1BitData = Asn1BitData::init_asn1();
	let mut v1 :Vec<u8>;
	a1.data = vec![0x22,0x22,0x22];
	let c = a1.encode_asn1().unwrap();
	v1 = vec![0x3,0x4,0x1,0x22,0x22,0x22];
	assert!(check_equal_u8(&v1,&c));
	v1 = vec![0x3,0x4,0x1,0x22,0x22,0x22];
	let s = a1.decode_asn1(&v1).unwrap();
	assert!(check_equal_u8(&a1.data,&v1[3..]));
	assert!(s == v1.len());
	return;
}

#[test]
fn test_a026() {
	let mut a1 :Asn1Any = Asn1Any::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"
			{{
				"{}" : 10,
				"{}" : [20,21,32]
			}}
		"#,ASN1_JSON_TAG,ASN1_JSON_CONTENT)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	let v1 = vec![20,21,32];
	assert!(a1.tag == 10);
	assert!(check_equal_u8(&a1.content,&v1));
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv[ASN1_JSON_TAG] == serde_json::json!(10) );
	assert!(cv[ASN1_JSON_CONTENT] == serde_json::json!([20,21,32]));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : 			{{
				"{}" : 10,
				"{}" : [20,21,32]
			}}
	}}
		"#,ASN1_JSON_TAG,ASN1_JSON_CONTENT)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	let v1 = vec![20,21,32];
	assert!(a1.tag == 10);
	assert!(check_equal_u8(&a1.content,&v1));
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"][ASN1_JSON_TAG] == serde_json::json!(10) );
	assert!(cv["hello"][ASN1_JSON_CONTENT] == serde_json::json!([20,21,32]));
}

#[test]
fn test_a027() {
	let mut a1 :Asn1Integer = Asn1Integer::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"10"#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == 10);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!(10) );
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : 10
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == 10);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!(10) );
}

#[test]
fn test_a028() {
	let mut a1 :Asn1Boolean = Asn1Boolean::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"true"#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == true);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!(true) );
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : false
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == false);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!(false) );
}

#[test]
fn test_a029() {
	let mut a1 :Asn1BitString = Asn1BitString::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#""ccval""#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == "ccval");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!("ccval") );
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : "bbval"
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == "bbval");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!("bbval"));
}

#[test]
fn test_a030() {
	let mut a1 :Asn1BitData = Asn1BitData::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"[20,20,33]"#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	let v1 = vec![20,20,33];
	assert!(check_equal_u8(&a1.data,&v1));
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!([20,20,33]));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : [21,25,77]
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	let v1 = vec![21,25,77];
	assert!(check_equal_u8(&a1.data,&v1));
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!([21,25,77]));
}

#[test]
fn test_a031() {
	let mut a1 :Asn1OctString = Asn1OctString::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#""cllc""#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == "cllc");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!("cllc"));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : "bbwww"
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == "bbwww");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!("bbwww"));
}

#[test]
fn test_a032() {
	let mut a1 :Asn1OctData = Asn1OctData::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"[20,20,33]"#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	let v1 = vec![20,20,33];
	assert!(check_equal_u8(&a1.data,&v1));
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!([20,20,33]));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : [21,25,77]
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	let v1 = vec![21,25,77];
	assert!(check_equal_u8(&a1.data,&v1));
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!([21,25,77]));
}

#[test]
fn test_a033() {
	let mut a1 :Asn1Null = Asn1Null::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"null"#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!(null));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : null
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!(null));
}

#[test]
fn test_a034() {
	let mut a1 :Asn1Object = Asn1Object::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#""2.3.111""#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.get_value() == "2.3.111");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!("2.3.111"));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : "2.3.111"
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.get_value() == "2.3.111");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(val["hello"] == serde_json::json!("2.3.111"));
}

#[test]
fn test_a035() {
	let mut a1 :Asn1Enumerated = Asn1Enumerated::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"10"#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == 10);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!(10) );
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : 10
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == 10);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!(10) );
}

#[test]
fn test_a036() {
	let mut a1 :Asn1String = Asn1String::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#""cllc""#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == "cllc");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!("cllc"));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : "bbwww"
	}}
		"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == "bbwww");
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!("bbwww"));
}

#[test]
fn test_a037() {
	let mut a1 :Asn1PrintableString = Asn1PrintableString::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"{}" : "cllc",
		"{}" : {}
	}}"#,ASN1_JSON_PRINTABLE_STRING,ASN1_JSON_INNER_FLAG,ASN1_UTF8STRING_FLAG)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == "cllc");
	assert!(a1.flag == ASN1_UTF8STRING_FLAG);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv[ASN1_JSON_PRINTABLE_STRING] == serde_json::json!("cllc"));
	assert!(cv[ASN1_JSON_INNER_FLAG] == serde_json::json!(ASN1_UTF8STRING_FLAG));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : {{
			"{}" : "bbwww",
			"{}" : {}
		}}
	}}
		"#,ASN1_JSON_PRINTABLE_STRING,ASN1_JSON_INNER_FLAG,ASN1_PRINTABLE2_FLAG)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == "bbwww");
	assert!(a1.flag == ASN1_PRINTABLE2_FLAG);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"][ASN1_JSON_PRINTABLE_STRING] == serde_json::json!("bbwww"));
	assert!(cv["hello"][ASN1_JSON_INNER_FLAG] == serde_json::json!(ASN1_PRINTABLE2_FLAG));
}

#[test]
fn test_a038() {
	let mut a1 :Asn1IA5String = Asn1IA5String::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"{}" : "cllc",
		"{}" : {}
	}}"#,ASN1_JSON_IA5STRING,ASN1_JSON_INNER_FLAG,ASN1_PRINTABLE2_FLAG)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == "cllc");
	assert!(a1.flag == ASN1_PRINTABLE2_FLAG);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv[ASN1_JSON_IA5STRING] == serde_json::json!("cllc"));
	assert!(cv[ASN1_JSON_INNER_FLAG] == serde_json::json!(ASN1_PRINTABLE2_FLAG));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : {{
			"{}" : "bbwww",
			"{}" : {}
		}}
	}}
		"#,ASN1_JSON_IA5STRING,ASN1_JSON_INNER_FLAG,ASN1_PRINTABLE2_FLAG)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == "bbwww");
	assert!(a1.flag == ASN1_PRINTABLE2_FLAG);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"][ASN1_JSON_IA5STRING] == serde_json::json!("bbwww"));
	assert!(cv["hello"][ASN1_JSON_INNER_FLAG] == serde_json::json!(ASN1_PRINTABLE2_FLAG));
}

#[test]
fn test_a039() {
	let mut a1 :Asn1Time = Asn1Time::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"{}" : "2022-12-01 10:20:39",
		"{}" : {}
	}}"#,ASN1_JSON_TIME,ASN1_JSON_INNER_FLAG,ASN1_GENERALTIME_FLAG)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.get_value_str() == "2022-12-01 10:20:39");
	assert!(a1.get_utag() == ASN1_GENERALTIME_FLAG);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv[ASN1_JSON_TIME] == serde_json::json!("2022-12-01 10:20:39"));
	assert!(cv[ASN1_JSON_INNER_FLAG] == serde_json::json!(ASN1_GENERALTIME_FLAG));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : {{
			"{}" : "2022-12-01 10:20:39",
			"{}" : {}
		}}
	}}
		"#,ASN1_JSON_TIME,ASN1_JSON_INNER_FLAG,ASN1_UTCTIME_FLAG)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.get_value_str() == "2022-12-01 10:20:39");
	assert!(a1.get_utag() == ASN1_UTCTIME_FLAG);
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"][ASN1_JSON_TIME] == serde_json::json!("2022-12-01 10:20:39"));
	assert!(cv["hello"][ASN1_JSON_INNER_FLAG] == serde_json::json!(ASN1_UTCTIME_FLAG));
}

#[test]
fn test_a040() {
	let mut a1 :Asn1BigNum = Asn1BigNum::init_asn1();
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#""2244ccddeeff""#)).unwrap();
	let _ = a1.decode_json("",&val).unwrap();
	assert!(a1.val == BigUint::parse_bytes(b"2244ccddeeff",16).unwrap());
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("",&mut cv).unwrap();
	assert!(cv == serde_json::json!("2244ccddeeff"));
	let val :serde_json::value::Value = serde_json::from_str(&format!(r#"{{
		"hello" : "2244ccddeefe"
	}}"#)).unwrap();
	let _ = a1.decode_json("hello",&val).unwrap();
	assert!(a1.val == BigUint::parse_bytes(b"2244ccddeefe",16).unwrap());
	let mut cv :serde_json::value::Value = serde_json::from_str("{}").unwrap();
	let _ = a1.encode_json("hello",&mut cv).unwrap();
	assert!(cv["hello"] == serde_json::json!("2244ccddeefe"));
}