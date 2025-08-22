
use std::marker::{PhantomData};
use serde::{Deserialize};
use std::error::Error;
use crate::base::{Asn1Any,Asn1BitDataFlag,Asn1Object,Asn1PrintableString,Asn1IA5String};
use crate::asn1impl::{Asn1Op};

use serde::de::{DeserializeOwned};
use std::str::FromStr;
use crate::*;
use crate::logger::*;
use crate::consts::*;

////////////////////////////////////////////////////////////////////////////////

pub struct OptionVisitor<T> {
	marker: PhantomData<T>,
}

impl<T> OptionVisitor<T> {
	pub fn new() -> Self {
		Self {
			marker :PhantomData,
		}
	}
}

impl<'de,T> serde::de::Visitor<'de> for OptionVisitor<T>
where
T: Deserialize<'de>,
{
	type Value = Option<T>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		formatter.write_str("option")
	}

	#[inline]
	fn visit_unit<E>(self) -> Result<Self::Value, E>
	where
	E: Error,
	{
		Ok(None)
	}

	#[inline]
	fn visit_none<E>(self) -> Result<Self::Value, E>
	where
	E: Error,
	{
		Ok(None)
	}

	#[inline]
	fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
	where
	D: serde::de::Deserializer<'de>,
	{
		T::deserialize(deserializer).map(Some)
	}

	fn __private_visit_untagged_option<D>(self, deserializer: D) -> Result<Self::Value, ()>
	where
	D: serde::de::Deserializer<'de>,
	{
		Ok(T::deserialize(deserializer).ok())
	}
}


pub struct VecVisitor<T : DeserializeOwned> {
	_mark :PhantomData<T>
}

impl<T:DeserializeOwned> VecVisitor<T> {
	pub fn new() -> Self {
		Self {
			_mark : PhantomData,
		}
	}
}

impl<'de,T :DeserializeOwned> serde::de::Visitor<'de> for VecVisitor<T>
{
	type Value = Vec<T>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		formatter.write_str("a sequence")
	}

	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
	where
	A: serde::de::SeqAccess<'de>,
	{
		let capacity = seq.size_hint().unwrap_or_else(|| 0);
		let mut values = Vec::<T>::with_capacity(capacity);

		loop {
			let ores = seq.next_element();
			match ores {
				Ok(val) => {
					if val.is_none() {
						break;
					}
					let value :T = val.unwrap();
					values.push(value);
				},
				Err(e) => {
					return Err(e);
				}
			}
		}

		Ok(values)
	}
}


#[allow(dead_code)]
pub struct Asn1AnyVisitor {
}

impl Asn1AnyVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for Asn1AnyVisitor {
	type Value = Asn1Any;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "a map need")
	}



	fn visit_map<A>(self, mut mapv: A) -> Result<Asn1Any, A::Error>
	where A: serde::de::MapAccess<'de>,
	{
		let mut oany :Asn1Any = Asn1Any::init_asn1();
		let mut tagv :Option<u64> = None;
		let mut contentv :Option<Vec<u8>> = None;

		while let Some(key) = mapv.next_key::<String>()? {
			match key.as_str() {
				ASN1_JSON_TAG => {

					if tagv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_TAG));
					}
					tagv = Some(mapv.next_value::<u64>()?);
				},
				ASN1_JSON_CONTENT => {
					if contentv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_CONTENT));
					}
					contentv = Some(mapv.next_value::<Vec<u8>>()?);
				},
				_ => {

				},
			}
		}

		if tagv.is_some() {
			oany.tag = tagv.as_ref().unwrap().clone();
		}

		if contentv.is_some() {
			oany.content = contentv.as_ref().unwrap().clone();
		}

		Ok(oany)
	}
}


#[allow(dead_code)]
#[derive(Clone,Copy)]
pub struct I64Visitor {
}

impl I64Visitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for I64Visitor {
	type Value = i64;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "i64 value")
	}
	fn visit_i64<E>(self, val :i64) -> Result<i64,E> 
		where E: serde::de::Error {
		Ok(val)
	}

	fn visit_u64<E>(self, val :u64) -> Result<i64,E> 
		where E: serde::de::Error {
		Ok(val as i64)
	}

	fn visit_str<E>(self,val :&str) -> Result<i64,E> 
		where E: serde::de::Error {
			let mut cparse :String = val.to_string();
			let mut base :u32 = 10;
		if val.starts_with("0x") || val.starts_with("0X") {
			cparse = cparse[2..].to_string();
			base = 16;
		} else if val.starts_with("x") || val.starts_with("X") {
			cparse = cparse[1..].to_string();
			base = 16;
		}
		asn1obj_log_trace!("put value {} parse value {}",val,cparse);
		i64::from_str_radix(&cparse,base).map_err(|err| {
			asn1obj_log_trace!("parse error {}", err);
			E::custom(format_args!("{} parse error {}",val,err))
		})
	}

}

pub struct BoolVisitor {}

impl BoolVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for BoolVisitor {
	type Value = bool;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "need bool")
	}
	fn visit_bool<E>(self, val :bool) -> Result<bool,E> 
		where E: serde::de::Error {
		Ok(val)
	}

}


pub struct StringVisitor {}

impl StringVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for StringVisitor {
	type Value = String;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "need bool")
	}
	fn visit_str<E>(self, val :&str) -> Result<String,E> 
		where E: serde::de::Error {
		let retv :String = format!("{}",val);
		Ok(retv)
	}

}


#[allow(dead_code)]
pub struct Asn1BitDataFlagVisitor {
}

impl Asn1BitDataFlagVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for Asn1BitDataFlagVisitor {
	type Value = Asn1BitDataFlag;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "a map need")
	}



	fn visit_map<A>(self, mut mapv: A) -> Result<Asn1BitDataFlag, A::Error>
	where A: serde::de::MapAccess<'de>,
	{
		let mut oany :Asn1BitDataFlag = Asn1BitDataFlag::init_asn1();
		let mut flagv :Option<u64> = None;
		let mut datav :Option<Vec<u8>> = None;

		while let Some(key) = mapv.next_key::<String>()? {
			match key.as_str() {
				ASN1_JSON_INNER_FLAG => {

					if flagv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_INNER_FLAG));
					}
					flagv = Some(mapv.next_value::<u64>()?);
				},
				ASN1_JSON_BITDATA => {
					if datav.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_BITDATA));
					}
					datav = Some(mapv.next_value::<Vec<u8>>()?);
				},
				_ => {

				},
			}
		}

		if flagv.is_some() {
			oany.flag = flagv.as_ref().unwrap().clone();
		}

		if datav.is_some() {
			oany.data = datav.as_ref().unwrap().clone();
		}

		Ok(oany)
	}
}


pub struct NullVisitor {
}

impl NullVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for NullVisitor
{
	type Value = Option<i32>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		formatter.write_str("null")
	}

	#[inline]
	fn visit_unit<E>(self) -> Result<Self::Value, E>
	where
	E: Error,
	{
		Ok(None)
	}

	#[inline]
	fn visit_none<E>(self) -> Result<Self::Value, E>
	where
	E: Error,
	{
		Ok(None)
	}
}


#[allow(dead_code)]
#[derive(Clone,Copy)]
pub struct Asn1ObjectVisitor {
}

impl Asn1ObjectVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for Asn1ObjectVisitor {
	type Value = Asn1Object;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "asn1object ")
	}

	fn visit_str<E>(self,val :&str) -> Result<Asn1Object,E> 
		where E: serde::de::Error {
		let mut retv :Asn1Object = Asn1Object::init_asn1();
		let ores = retv.set_value(val);
		if ores.is_err() {
			let err = E::custom(format_args!("{:?}",ores.err().unwrap()));
			return Err(err);
		}
		Ok(retv)
	}


	fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
	where
	A: serde::de::SeqAccess<'de>,
	{
		let capacity = seq.size_hint().unwrap_or_else(|| 0);
		let mut values = Vec::<i64>::with_capacity(capacity);

		loop {
			let ores = seq.next_element();
			match ores {
				Ok(val) => {
					if val.is_none() {
						break;
					}
					let value :i64 = val.unwrap();
					values.push(value);
				},
				Err(e) => {
					return Err(e);
				}
			}
		}

		/*now to give the string value*/
		let mut oids :String = "".to_string();
		let mut idx :usize=0;

		while idx < values.len() {
			if idx > 0 {
				oids.push_str(".");
			}
			oids.push_str(&format!("{}",values[idx]));
			idx += 1;
		}

		let mut retv :Asn1Object = Asn1Object::init_asn1();
		let ores = retv.set_value(&oids);
		if ores.is_err() {
			let err = serde::de::Error::custom(format_args!("{:?}",ores.err().unwrap()));
			return Err(err);
		}
		Ok(retv)

	}


}


#[allow(dead_code)]
pub struct Asn1PrintableStringVisitor {
}

impl Asn1PrintableStringVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for Asn1PrintableStringVisitor {
	type Value = Asn1PrintableString;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "a map need")
	}



	fn visit_map<A>(self, mut mapv: A) -> Result<Asn1PrintableString, A::Error>
	where A: serde::de::MapAccess<'de>,
	{
		let mut oany :Asn1PrintableString = Asn1PrintableString::init_asn1();
		let mut tagv :Option<u64> = None;
		let mut contentv :Option<String> = None;

		while let Some(key) = mapv.next_key::<String>()? {
			match key.as_str() {
				ASN1_JSON_INNER_FLAG => {

					if tagv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_INNER_FLAG));
					}
					tagv = Some(mapv.next_value::<u64>()?);
				},
				ASN1_JSON_PRINTABLE_STRING => {
					if contentv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_PRINTABLE_STRING));
					}
					let ostr :String = mapv.next_value::<String>()?;
					contentv = Some(format!("{}",ostr));
					
				},
				_ => {

				},
			}
		}

		if tagv.is_some() {
			oany.flag = (*tagv.as_ref().unwrap()) as u8;
		}

		if contentv.is_some() {
			oany.val = format!("{}",contentv.as_ref().unwrap());
		}

		Ok(oany)
	}
}


#[allow(dead_code)]
pub struct Asn1IA5StringVisitor {
}

impl Asn1IA5StringVisitor {
	pub fn new() -> Self {
		Self {
		}
	}
}

impl<'de> serde::de::Visitor<'de> for Asn1IA5StringVisitor {
	type Value = Asn1IA5String;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "a map need")
	}



	fn visit_map<A>(self, mut mapv: A) -> Result<Asn1IA5String, A::Error>
	where A: serde::de::MapAccess<'de>,
	{
		let mut oany :Asn1IA5String = Asn1IA5String::init_asn1();
		let mut tagv :Option<u64> = None;
		let mut contentv :Option<String> = None;

		while let Some(key) = mapv.next_key::<String>()? {
			match key.as_str() {
				ASN1_JSON_INNER_FLAG => {

					if tagv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_INNER_FLAG));
					}
					tagv = Some(mapv.next_value::<u64>()?);
				},
				ASN1_JSON_IA5STRING => {
					if contentv.is_some() {
						return Err(serde::de::Error::duplicate_field(ASN1_JSON_IA5STRING));
					}
					let ostr :String = mapv.next_value::<String>()?;
					contentv = Some(format!("{}",ostr));
					
				},
				_ => {

				},
			}
		}

		if tagv.is_some() {
			oany.flag = (*tagv.as_ref().unwrap()) as u8;
		}

		if contentv.is_some() {
			oany.val = format!("{}",contentv.as_ref().unwrap());
		}

		Ok(oany)
	}
}