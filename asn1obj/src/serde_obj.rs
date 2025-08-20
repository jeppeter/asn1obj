
use std::marker::{PhantomData};
use serde::{Deserialize};
use std::error::Error;
use crate::base::{Asn1Any};
use crate::asn1impl::{Asn1Op};

//use serde::de::{DeserializeOwned};

////////////////////////////////////////////////////////////////////////////////

pub struct OptionVisitor<'de,T> {
	marker: PhantomData<&'de T>,
}

impl<'de,T> OptionVisitor<'de,T> {
	pub fn new() -> Self {
		Self {
			marker: PhantomData,
		}
	}
}

impl<'de,T> serde::de::Visitor<'de> for OptionVisitor<'de,T>
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


pub struct VecVisitor<'de,T> {
	marker: PhantomData<&'de T>,
}

impl<'de,T> VecVisitor<'de,T> {
	pub fn new() -> Self {
		Self {
			marker:PhantomData,
		}
	}
}

impl<'de,T> serde::de::Visitor<'de> for VecVisitor<'de,T>
where
T: Deserialize<'de>,
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
pub struct Asn1AnyVisitor<'de> {
	_mark :PhantomData<&'de u64>,
}

impl<'de> Asn1AnyVisitor<'de> {
	pub fn new() -> Self {
		Self {
			_mark :PhantomData,
		}
	}
}

impl<'de> serde::de::Visitor<'de> for Asn1AnyVisitor<'de> {
	type Value = Asn1Any<'de>;

	fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(formatter, "a map need")
	}



	fn visit_map<A>(self, mut mapv: A) -> Result<Asn1Any<'de>, A::Error>
	where A: serde::de::MapAccess<'de>,
	{
		let mut oany :Asn1Any<'de> = Asn1Any::<'de>::init_asn1();
		let mut tagv :Option<u64> = None;
		let mut contentv :Option<Vec<u8>> = None;

		while let Some(key) = mapv.next_key::<String>()? {
			match key.as_str() {
				"tag" => {

					if tagv.is_some() {
						return Err(serde::de::Error::duplicate_field("tag"));
					}
					tagv = Some(mapv.next_value::<u64>()?);
				},
				"content" => {
					if contentv.is_some() {
						return Err(serde::de::Error::duplicate_field("content"));
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



