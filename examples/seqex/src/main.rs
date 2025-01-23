use asn1obj_codegen::{asn1_sequence};
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::base::*;
use asn1obj::complex::*;
use asn1obj::asn1impl::Asn1Op;
 use asn1obj::strop::asn1_format_line;

use num_bigint::{BigUint};
use hex::FromHex;
use std::error::Error;
use std::io::Write;
use serde_json;

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkeyElem {
	#[asn1_ext(noasn1)]
	pub c :Asn1BigNum,
	pub n :Asn1BigNum,
	pub e :Asn1BigNum,
}

#[asn1_sequence()]
#[derive(Clone)]
pub struct Asn1RsaPubkey {
	pub elem :Asn1Seq<Asn1RsaPubkeyElem>,
}

fn format_vecs(buf :&[u8], tab :i32) -> String {
	let mut outs :String = "".to_string();
	let mut lasti : usize = 0;
	let mut ki :usize;
	for i in 0..buf.len() {
		if (i%16) == 0 {
			if i > 0 {
				outs.push_str("    ");
				while lasti != i {
					if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
						outs.push(buf[lasti] as char);
					} else {
						outs.push_str(".");
					}
					lasti += 1;
				}
				outs.push_str("\n");
			}

			for _j in 0..tab {
				outs.push_str("    ");
			}
		}
		if (i % 16) == 0 {
			outs.push_str(&format!("{:02x}", buf[i]));	
		} else {
			outs.push_str(&format!(":{:02x}", buf[i]));	
		}
		
	}

	if lasti != buf.len() {
		ki = buf.len();
		while (ki % 16) != 0 {
			outs.push_str("   ");
			ki += 1;
		}
		outs.push_str("    ");
		while lasti != buf.len() {
			if buf[lasti] >= 0x20 && buf[lasti] <= 0x7e {
				outs.push(buf[lasti] as char);
			} else {
				outs.push_str(".");
			}
			lasti += 1;
		}
	}
	outs.push_str("\n");
	return outs;
}


fn main() -> Result<(),Box<dyn Error>> {
	let mut pubkey :Asn1RsaPubkey = Asn1RsaPubkey::init_asn1();
	let mut pubkeyelem :Asn1RsaPubkeyElem = Asn1RsaPubkeyElem::init_asn1();
	let nv :Vec<u8> = Vec::from_hex("df45f6d9925fe470dcb55c26afe0dfd6a0307cf9287342749b7341b342f87fa2b5238245ac73788b0016015834c59fd0481cb9cb97f575f13abd600799b3a2113ec2e4c22385fd45674326ffc55fa84ab2088063f48e8efeb7dd473194a079fabd96d4f59f70ccc0bb78628bc89725519cd57a180e54fd6608ef2d401124ed5e23598329eb13e2dd0ebdd7692bff9a07ce57ec50b1b3bc6d585d2585f96fc9276ed2d36b834420bd1b96f7a4e2b913795fe8744a2046ba537b18104ee98a8b7b959e009742091814211b15c6a5992f46c5a74b9398a47b01d20fc35228f174c617ca3ab2e89944147150c24c7619db1666bf0d447630683dea078274d8d3069d")?;
	let ne :Vec<u8> = Vec::from_hex("010001")?;
	pubkeyelem.n.val = BigUint::from_bytes_be(&nv);
	pubkeyelem.e.val = BigUint::from_bytes_be(&ne);
	pubkey.elem.val.push(pubkeyelem);
	let outd = pubkey.encode_asn1()?;
	let s = format_vecs(&outd,1);
	let mut outs :String = "".to_string();
	let mut outf = std::io::stdout();
	outs.push_str("outs\n");
	outs.push_str(&s);
	std::io::stdout().write(outs.as_bytes())?;
	pubkey.print_asn1("Rsa Public Key",0,&mut outf)?;
	Ok(())
}
/*
output:
outs
    30:82:01:0a:02:82:01:01:00:df:45:f6:d9:92:5f:e4    0.........E..._.
    70:dc:b5:5c:26:af:e0:df:d6:a0:30:7c:f9:28:73:42    p..\&.....0|.(sB
    74:9b:73:41:b3:42:f8:7f:a2:b5:23:82:45:ac:73:78    t.sA.B....#.E.sx
    8b:00:16:01:58:34:c5:9f:d0:48:1c:b9:cb:97:f5:75    ....X4...H.....u
    f1:3a:bd:60:07:99:b3:a2:11:3e:c2:e4:c2:23:85:fd    .:.`.....>...#..
    45:67:43:26:ff:c5:5f:a8:4a:b2:08:80:63:f4:8e:8e    EgC&.._.J...c...
    fe:b7:dd:47:31:94:a0:79:fa:bd:96:d4:f5:9f:70:cc    ...G1..y......p.
    c0:bb:78:62:8b:c8:97:25:51:9c:d5:7a:18:0e:54:fd    ..xb...%Q..z..T.
    66:08:ef:2d:40:11:24:ed:5e:23:59:83:29:eb:13:e2    f..-@.$.^#Y.)...
    dd:0e:bd:d7:69:2b:ff:9a:07:ce:57:ec:50:b1:b3:bc    ....i+....W.P...
    6d:58:5d:25:85:f9:6f:c9:27:6e:d2:d3:6b:83:44:20    mX]%..o.'n..k.D 
    bd:1b:96:f7:a4:e2:b9:13:79:5f:e8:74:4a:20:46:ba    ........y_.tJ F.
    53:7b:18:10:4e:e9:8a:8b:7b:95:9e:00:97:42:09:18    S{..N...{....B..
    14:21:1b:15:c6:a5:99:2f:46:c5:a7:4b:93:98:a4:7b    .!...../F..K...{
    01:d2:0f:c3:52:28:f1:74:c6:17:ca:3a:b2:e8:99:44    ....R(.t...:...D
    14:71:50:c2:4c:76:19:db:16:66:bf:0d:44:76:30:68    .qP.Lv...f..Dv0h
    3d:ea:07:82:74:d8:d3:06:9d:02:03:01:00:01          =...t.........
Rsa Public Key[0] Asn1RsaPubkeyElem
    n: ASN1_BIGNUM
        df:45:f6:d9:92:5f:e4:70:dc:b5:5c:26:af:e0:df:d6    .E..._.p..\&....
        a0:30:7c:f9:28:73:42:74:9b:73:41:b3:42:f8:7f:a2    .0|.(sBt.sA.B...
        b5:23:82:45:ac:73:78:8b:00:16:01:58:34:c5:9f:d0    .#.E.sx....X4...
        48:1c:b9:cb:97:f5:75:f1:3a:bd:60:07:99:b3:a2:11    H.....u.:.`.....
        3e:c2:e4:c2:23:85:fd:45:67:43:26:ff:c5:5f:a8:4a    >...#..EgC&.._.J
        b2:08:80:63:f4:8e:8e:fe:b7:dd:47:31:94:a0:79:fa    ...c......G1..y.
        bd:96:d4:f5:9f:70:cc:c0:bb:78:62:8b:c8:97:25:51    .....p...xb...%Q
        9c:d5:7a:18:0e:54:fd:66:08:ef:2d:40:11:24:ed:5e    ..z..T.f..-@.$.^
        23:59:83:29:eb:13:e2:dd:0e:bd:d7:69:2b:ff:9a:07    #Y.).......i+...
        ce:57:ec:50:b1:b3:bc:6d:58:5d:25:85:f9:6f:c9:27    .W.P...mX]%..o.'
        6e:d2:d3:6b:83:44:20:bd:1b:96:f7:a4:e2:b9:13:79    n..k.D ........y
        5f:e8:74:4a:20:46:ba:53:7b:18:10:4e:e9:8a:8b:7b    _.tJ F.S{..N...{
        95:9e:00:97:42:09:18:14:21:1b:15:c6:a5:99:2f:46    ....B...!...../F
        c5:a7:4b:93:98:a4:7b:01:d2:0f:c3:52:28:f1:74:c6    ..K...{....R(.t.
        17:ca:3a:b2:e8:99:44:14:71:50:c2:4c:76:19:db:16    ..:...D.qP.Lv...
        66:bf:0d:44:76:30:68:3d:ea:07:82:74:d8:d3:06:9d    f..Dv0h=...t....
    e: ASN1_BIGNUM 0x00010001
*/