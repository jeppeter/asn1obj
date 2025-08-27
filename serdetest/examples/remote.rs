/*
#[derive(Clone,Debug,Serialize,Deserialize)]
enum DeriveEnum {
    Enum1,
    Enum3,
    EnumCC,
}

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(remote = "Asn1OctData")]
struct NAsn1OctData {
    pub data :Vec<u8>,
}


impl TryFrom<i32> for DeriveEnum {
    type Error = String;

    fn try_from(v :i32)  -> Result<Self,Self::Error> {
        match v {
            0 => {return Ok(DeriveEnum::Enum1);},
            1 => {return Ok(DeriveEnum::Enum3);},
            2 => {return Ok(DeriveEnum::EnumCC);},
            _ => {return Err(format!("not valid value {}",v));},
        }
    }
}

impl Into<i32> for DeriveEnum {
    fn into(self) -> i32 {
        match self {
            DeriveEnum::Enum1 => {return 0;},
            DeriveEnum::Enum3 => {return 1;},
            DeriveEnum::EnumCC => {return 2;},
        }
    }
}


//#[derive(Debug,Clone)]
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
struct BaseStruct {
    pub name2 :Vec<String>,
    pub cc2 :Vec<i32>,
}

//#[derive(Debug,Clone)]
#[derive(Clone,Debug,Serialize,Deserialize)]
struct NoPatternStruct {
    pub name :Vec<String>,
    pub cc :Vec<i32>,
}

impl Default for NoPatternStruct {
    fn default() -> Self {
        Self {
            name :vec![],
            cc :vec![],
        }
    }
}


//#[derive(Debug,Clone)]
#[allow(non_snake_case)]
#[derive(Clone,Debug,serde::Serialize,serde::Deserialize)]
struct DeriveStruct {
    pub basenew :Vec<BaseStruct>,
    pub pattern :NoPatternStruct,
    pub enumval :DeriveEnum,
    pub strval :NAsn1OctData,
}


*/


#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl _serde :: Serialize for
    DeriveEnum
    {
        fn serialize < __S > (& self, __serializer : __S) -> _serde ::
        __private :: Result < __S :: Ok, __S :: Error > where __S : _serde ::
        Serializer,
        {
            match * self
            {
                DeriveEnum :: Enum1 => _serde :: Serializer ::
                serialize_unit_variant(__serializer, "DeriveEnum", 0u32,
                "Enum1",), DeriveEnum :: Enum3 => _serde :: Serializer ::
                serialize_unit_variant(__serializer, "DeriveEnum", 1u32,
                "Enum3",), DeriveEnum :: EnumCC => _serde :: Serializer ::
                serialize_unit_variant(__serializer, "DeriveEnum", 2u32,
                "EnumCC",),
            }
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl < 'de > _serde ::
    Deserialize < 'de > for DeriveEnum
    {
        fn deserialize < __D > (__deserializer : __D) -> _serde :: __private
        :: Result < Self, __D :: Error > where __D : _serde :: Deserializer <
        'de > ,
        {
            #[allow(non_camel_case_types)] #[doc(hidden)] enum __Field
            { __field0, __field1, __field2, } #[doc(hidden)] struct
            __FieldVisitor; #[automatically_derived] impl < 'de > _serde :: de
            :: Visitor < 'de > for __FieldVisitor
            {
                type Value = __Field; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "variant identifier")
                } fn visit_u64 < __E > (self, __value : u64) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        0u64 => _serde :: __private :: Ok(__Field :: __field0), 1u64
                        => _serde :: __private :: Ok(__Field :: __field1), 2u64 =>
                        _serde :: __private :: Ok(__Field :: __field2), _ => _serde
                        :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_value(_serde :: de :: Unexpected ::
                        Unsigned(__value), & "variant index 0 <= i < 3",)),
                    }
                } fn visit_str < __E > (self, __value : & str) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        "Enum1" => _serde :: __private :: Ok(__Field :: __field0),
                        "Enum3" => _serde :: __private :: Ok(__Field :: __field1),
                        "EnumCC" => _serde :: __private :: Ok(__Field :: __field2),
                        _ =>
                        {
                            _serde :: __private ::
                            Err(_serde :: de :: Error ::
                            unknown_variant(__value, VARIANTS))
                        }
                    }
                } fn visit_bytes < __E > (self, __value : & [u8]) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        b"Enum1" => _serde :: __private :: Ok(__Field :: __field0),
                        b"Enum3" => _serde :: __private :: Ok(__Field :: __field1),
                        b"EnumCC" => _serde :: __private :: Ok(__Field :: __field2),
                        _ =>
                        {
                            let __value = & _serde :: __private ::
                            from_utf8_lossy(__value); _serde :: __private ::
                            Err(_serde :: de :: Error ::
                            unknown_variant(__value, VARIANTS))
                        }
                    }
                }
            } #[automatically_derived] impl < 'de > _serde :: Deserialize <
            'de > for __Field
            {
                #[inline] fn deserialize < __D > (__deserializer : __D) ->
                _serde :: __private :: Result < Self, __D :: Error > where __D
                : _serde :: Deserializer < 'de > ,
                {
                    _serde :: Deserializer ::
                    deserialize_identifier(__deserializer, __FieldVisitor)
                }
            } #[doc(hidden)] struct __Visitor < 'de >
            {
                marker : _serde :: __private :: PhantomData < DeriveEnum > ,
                lifetime : _serde :: __private :: PhantomData < & 'de () > ,
            } #[automatically_derived] impl < 'de > _serde :: de :: Visitor <
            'de > for __Visitor < 'de >
            {
                type Value = DeriveEnum; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "enum DeriveEnum")
                } fn visit_enum < __A > (self, __data : __A) -> _serde ::
                __private :: Result < Self :: Value, __A :: Error > where __A
                : _serde :: de :: EnumAccess < 'de > ,
                {
                    match _serde :: de :: EnumAccess :: variant(__data) ?
                    {
                        (__Field :: __field0, __variant) =>
                        {
                            _serde :: de :: VariantAccess :: unit_variant(__variant) ? ;
                            _serde :: __private :: Ok(DeriveEnum :: Enum1)
                        } (__Field :: __field1, __variant) =>
                        {
                            _serde :: de :: VariantAccess :: unit_variant(__variant) ? ;
                            _serde :: __private :: Ok(DeriveEnum :: Enum3)
                        } (__Field :: __field2, __variant) =>
                        {
                            _serde :: de :: VariantAccess :: unit_variant(__variant) ? ;
                            _serde :: __private :: Ok(DeriveEnum :: EnumCC)
                        }
                    }
                }
            } #[doc(hidden)] const VARIANTS : & 'static [& 'static str] = &
            ["Enum1", "Enum3", "EnumCC"]; _serde :: Deserializer ::
            deserialize_enum(__deserializer, "DeriveEnum", VARIANTS, __Visitor
            {
                marker : _serde :: __private :: PhantomData :: < DeriveEnum >
                , lifetime : _serde :: __private :: PhantomData,
            },)
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl NAsn1OctData
    {
        fn serialize < __S > (__self : & Asn1OctData, __serializer : __S) ->
        _serde :: __private :: Result < __S :: Ok, __S :: Error > where __S :
        _serde :: Serializer,
        {
            match _serde :: __private :: None :: < & NAsn1OctData >
            {
                _serde :: __private :: Some(NAsn1OctData { data : __v0 }) =>
                {} _ => {}
            } let mut __serde_state = _serde :: Serializer ::
            serialize_struct(__serializer, "NAsn1OctData", false as usize + 1)
            ? ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "data", _serde :: __private
            :: ser :: constrain :: < Vec < u8 > > (& __self.data)) ? ; _serde
            :: ser :: SerializeStruct :: end(__serde_state)
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl < 'de > NAsn1OctData
    {
        fn deserialize < __D > (__deserializer : __D) -> _serde :: __private
        :: Result < Asn1OctData, __D :: Error > where __D : _serde ::
        Deserializer < 'de > ,
        {
            match _serde :: __private :: None :: < & NAsn1OctData >
            {
                _serde :: __private :: Some(NAsn1OctData { data : __v0 }) =>
                {} _ => {}
            } #[allow(non_camel_case_types)] #[doc(hidden)] enum __Field
            { __field0, __ignore, } #[doc(hidden)] struct __FieldVisitor;
            #[automatically_derived] impl < 'de > _serde :: de :: Visitor <
            'de > for __FieldVisitor
            {
                type Value = __Field; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "field identifier")
                } fn visit_u64 < __E > (self, __value : u64) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        0u64 => _serde :: __private :: Ok(__Field :: __field0), _ =>
                        _serde :: __private :: Ok(__Field :: __ignore),
                    }
                } fn visit_str < __E > (self, __value : & str) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        "data" => _serde :: __private :: Ok(__Field :: __field0), _
                        => { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                } fn visit_bytes < __E > (self, __value : & [u8]) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        b"data" => _serde :: __private :: Ok(__Field :: __field0), _
                        => { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                }
            } #[automatically_derived] impl < 'de > _serde :: Deserialize <
            'de > for __Field
            {
                #[inline] fn deserialize < __D > (__deserializer : __D) ->
                _serde :: __private :: Result < Self, __D :: Error > where __D
                : _serde :: Deserializer < 'de > ,
                {
                    _serde :: Deserializer ::
                    deserialize_identifier(__deserializer, __FieldVisitor)
                }
            } #[doc(hidden)] struct __Visitor < 'de >
            {
                marker : _serde :: __private :: PhantomData < Asn1OctData > ,
                lifetime : _serde :: __private :: PhantomData < & 'de () > ,
            } #[automatically_derived] impl < 'de > _serde :: de :: Visitor <
            'de > for __Visitor < 'de >
            {
                type Value = Asn1OctData; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "struct Asn1OctData")
                } #[inline] fn visit_seq < __A > (self, mut __seq : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: SeqAccess < 'de > ,
                {
                    let __field0 = match _serde :: de :: SeqAccess ::
                    next_element :: < Vec < u8 > > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(0usize, &
                        "struct Asn1OctData with 1 element")),
                    }; _serde :: __private ::
                    Ok(Asn1OctData { data : __field0 })
                } #[inline] fn visit_map < __A > (self, mut __map : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: MapAccess < 'de > ,
                {
                    let mut __field0 : _serde :: __private :: Option < Vec < u8
                    > > = _serde :: __private :: None; while let _serde ::
                    __private :: Some(__key) = _serde :: de :: MapAccess ::
                    next_key :: < __Field > (& mut __map) ?
                    {
                        match __key
                        {
                            __Field :: __field0 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field0)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("data"));
                                } __field0 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < Vec < u8 >
                                > (& mut __map) ?);
                            } _ =>
                            {
                                let _ = _serde :: de :: MapAccess :: next_value :: < _serde
                                :: de :: IgnoredAny > (& mut __map) ? ;
                            }
                        }
                    } let __field0 = match __field0
                    {
                        _serde :: __private :: Some(__field0) => __field0, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("data") ? ,
                    }; _serde :: __private ::
                    Ok(Asn1OctData { data : __field0 })
                }
            } #[doc(hidden)] const FIELDS : & 'static [& 'static str] = &
            ["data"]; _serde :: Deserializer ::
            deserialize_struct(__deserializer, "NAsn1OctData", FIELDS,
            __Visitor
            {
                marker : _serde :: __private :: PhantomData :: < Asn1OctData >
                , lifetime : _serde :: __private :: PhantomData,
            })
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl _serde :: Serialize for
    BaseStruct
    {
        fn serialize < __S > (& self, __serializer : __S) -> _serde ::
        __private :: Result < __S :: Ok, __S :: Error > where __S : _serde ::
        Serializer,
        {
            let mut __serde_state = _serde :: Serializer ::
            serialize_struct(__serializer, "BaseStruct", false as usize + 1 +
            1) ? ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "name2", & self.name2) ? ;
            _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "cc2", & self.cc2) ? ; _serde
            :: ser :: SerializeStruct :: end(__serde_state)
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl < 'de > _serde ::
    Deserialize < 'de > for BaseStruct
    {
        fn deserialize < __D > (__deserializer : __D) -> _serde :: __private
        :: Result < Self, __D :: Error > where __D : _serde :: Deserializer <
        'de > ,
        {
            #[allow(non_camel_case_types)] #[doc(hidden)] enum __Field
            { __field0, __field1, __ignore, } #[doc(hidden)] struct
            __FieldVisitor; #[automatically_derived] impl < 'de > _serde :: de
            :: Visitor < 'de > for __FieldVisitor
            {
                type Value = __Field; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "field identifier")
                } fn visit_u64 < __E > (self, __value : u64) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        0u64 => _serde :: __private :: Ok(__Field :: __field0), 1u64
                        => _serde :: __private :: Ok(__Field :: __field1), _ =>
                        _serde :: __private :: Ok(__Field :: __ignore),
                    }
                } fn visit_str < __E > (self, __value : & str) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        "name2" => _serde :: __private :: Ok(__Field :: __field0),
                        "cc2" => _serde :: __private :: Ok(__Field :: __field1), _
                        => { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                } fn visit_bytes < __E > (self, __value : & [u8]) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        b"name2" => _serde :: __private :: Ok(__Field :: __field0),
                        b"cc2" => _serde :: __private :: Ok(__Field :: __field1), _
                        => { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                }
            } #[automatically_derived] impl < 'de > _serde :: Deserialize <
            'de > for __Field
            {
                #[inline] fn deserialize < __D > (__deserializer : __D) ->
                _serde :: __private :: Result < Self, __D :: Error > where __D
                : _serde :: Deserializer < 'de > ,
                {
                    _serde :: Deserializer ::
                    deserialize_identifier(__deserializer, __FieldVisitor)
                }
            } #[doc(hidden)] struct __Visitor < 'de >
            {
                marker : _serde :: __private :: PhantomData < BaseStruct > ,
                lifetime : _serde :: __private :: PhantomData < & 'de () > ,
            } #[automatically_derived] impl < 'de > _serde :: de :: Visitor <
            'de > for __Visitor < 'de >
            {
                type Value = BaseStruct; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "struct BaseStruct")
                } #[inline] fn visit_seq < __A > (self, mut __seq : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: SeqAccess < 'de > ,
                {
                    let __field0 = match _serde :: de :: SeqAccess ::
                    next_element :: < Vec < String > > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(0usize, &
                        "struct BaseStruct with 2 elements")),
                    }; let __field1 = match _serde :: de :: SeqAccess ::
                    next_element :: < Vec < i32 > > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(1usize, &
                        "struct BaseStruct with 2 elements")),
                    }; _serde :: __private ::
                    Ok(BaseStruct { name2 : __field0, cc2 : __field1 })
                } #[inline] fn visit_map < __A > (self, mut __map : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: MapAccess < 'de > ,
                {
                    let mut __field0 : _serde :: __private :: Option < Vec <
                    String > > = _serde :: __private :: None; let mut __field1 :
                    _serde :: __private :: Option < Vec < i32 > > = _serde ::
                    __private :: None; while let _serde :: __private ::
                    Some(__key) = _serde :: de :: MapAccess :: next_key :: <
                    __Field > (& mut __map) ?
                    {
                        match __key
                        {
                            __Field :: __field0 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field0)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("name2"));
                                } __field0 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < Vec <
                                String > > (& mut __map) ?);
                            } __Field :: __field1 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field1)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("cc2"));
                                } __field1 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < Vec < i32
                                > > (& mut __map) ?);
                            } _ =>
                            {
                                let _ = _serde :: de :: MapAccess :: next_value :: < _serde
                                :: de :: IgnoredAny > (& mut __map) ? ;
                            }
                        }
                    } let __field0 = match __field0
                    {
                        _serde :: __private :: Some(__field0) => __field0, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("name2") ? ,
                    }; let __field1 = match __field1
                    {
                        _serde :: __private :: Some(__field1) => __field1, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("cc2") ? ,
                    }; _serde :: __private ::
                    Ok(BaseStruct { name2 : __field0, cc2 : __field1 })
                }
            } #[doc(hidden)] const FIELDS : & 'static [& 'static str] = &
            ["name2", "cc2"]; _serde :: Deserializer ::
            deserialize_struct(__deserializer, "BaseStruct", FIELDS, __Visitor
            {
                marker : _serde :: __private :: PhantomData :: < BaseStruct >
                , lifetime : _serde :: __private :: PhantomData,
            })
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl _serde :: Serialize for
    NoPatternStruct
    {
        fn serialize < __S > (& self, __serializer : __S) -> _serde ::
        __private :: Result < __S :: Ok, __S :: Error > where __S : _serde ::
        Serializer,
        {
            let mut __serde_state = _serde :: Serializer ::
            serialize_struct(__serializer, "NoPatternStruct", false as usize +
            1 + 1) ? ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "name", & self.name) ? ;
            _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "cc", & self.cc) ? ; _serde
            :: ser :: SerializeStruct :: end(__serde_state)
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl < 'de > _serde ::
    Deserialize < 'de > for NoPatternStruct
    {
        fn deserialize < __D > (__deserializer : __D) -> _serde :: __private
        :: Result < Self, __D :: Error > where __D : _serde :: Deserializer <
        'de > ,
        {
            #[allow(non_camel_case_types)] #[doc(hidden)] enum __Field
            { __field0, __field1, __ignore, } #[doc(hidden)] struct
            __FieldVisitor; #[automatically_derived] impl < 'de > _serde :: de
            :: Visitor < 'de > for __FieldVisitor
            {
                type Value = __Field; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "field identifier")
                } fn visit_u64 < __E > (self, __value : u64) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        0u64 => _serde :: __private :: Ok(__Field :: __field0), 1u64
                        => _serde :: __private :: Ok(__Field :: __field1), _ =>
                        _serde :: __private :: Ok(__Field :: __ignore),
                    }
                } fn visit_str < __E > (self, __value : & str) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        "name" => _serde :: __private :: Ok(__Field :: __field0),
                        "cc" => _serde :: __private :: Ok(__Field :: __field1), _ =>
                        { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                } fn visit_bytes < __E > (self, __value : & [u8]) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        b"name" => _serde :: __private :: Ok(__Field :: __field0),
                        b"cc" => _serde :: __private :: Ok(__Field :: __field1), _
                        => { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                }
            } #[automatically_derived] impl < 'de > _serde :: Deserialize <
            'de > for __Field
            {
                #[inline] fn deserialize < __D > (__deserializer : __D) ->
                _serde :: __private :: Result < Self, __D :: Error > where __D
                : _serde :: Deserializer < 'de > ,
                {
                    _serde :: Deserializer ::
                    deserialize_identifier(__deserializer, __FieldVisitor)
                }
            } #[doc(hidden)] struct __Visitor < 'de >
            {
                marker : _serde :: __private :: PhantomData < NoPatternStruct
                > , lifetime : _serde :: __private :: PhantomData < & 'de () >
                ,
            } #[automatically_derived] impl < 'de > _serde :: de :: Visitor <
            'de > for __Visitor < 'de >
            {
                type Value = NoPatternStruct; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "struct NoPatternStruct")
                } #[inline] fn visit_seq < __A > (self, mut __seq : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: SeqAccess < 'de > ,
                {
                    let __field0 = match _serde :: de :: SeqAccess ::
                    next_element :: < Vec < String > > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(0usize, &
                        "struct NoPatternStruct with 2 elements")),
                    }; let __field1 = match _serde :: de :: SeqAccess ::
                    next_element :: < Vec < i32 > > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(1usize, &
                        "struct NoPatternStruct with 2 elements")),
                    }; _serde :: __private ::
                    Ok(NoPatternStruct { name : __field0, cc : __field1 })
                } #[inline] fn visit_map < __A > (self, mut __map : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: MapAccess < 'de > ,
                {
                    let mut __field0 : _serde :: __private :: Option < Vec <
                    String > > = _serde :: __private :: None; let mut __field1 :
                    _serde :: __private :: Option < Vec < i32 > > = _serde ::
                    __private :: None; while let _serde :: __private ::
                    Some(__key) = _serde :: de :: MapAccess :: next_key :: <
                    __Field > (& mut __map) ?
                    {
                        match __key
                        {
                            __Field :: __field0 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field0)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("name"));
                                } __field0 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < Vec <
                                String > > (& mut __map) ?);
                            } __Field :: __field1 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field1)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("cc"));
                                } __field1 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < Vec < i32
                                > > (& mut __map) ?);
                            } _ =>
                            {
                                let _ = _serde :: de :: MapAccess :: next_value :: < _serde
                                :: de :: IgnoredAny > (& mut __map) ? ;
                            }
                        }
                    } let __field0 = match __field0
                    {
                        _serde :: __private :: Some(__field0) => __field0, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("name") ? ,
                    }; let __field1 = match __field1
                    {
                        _serde :: __private :: Some(__field1) => __field1, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("cc") ? ,
                    }; _serde :: __private ::
                    Ok(NoPatternStruct { name : __field0, cc : __field1 })
                }
            } #[doc(hidden)] const FIELDS : & 'static [& 'static str] = &
            ["name", "cc"]; _serde :: Deserializer ::
            deserialize_struct(__deserializer, "NoPatternStruct", FIELDS,
            __Visitor
            {
                marker : _serde :: __private :: PhantomData :: <
                NoPatternStruct > , lifetime : _serde :: __private ::
                PhantomData,
            })
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl _serde :: Serialize for
    DeriveStruct
    {
        fn serialize < __S > (& self, __serializer : __S) -> _serde ::
        __private :: Result < __S :: Ok, __S :: Error > where __S : _serde ::
        Serializer,
        {
            let mut __serde_state = _serde :: Serializer ::
            serialize_struct(__serializer, "DeriveStruct", false as usize + 1
            + 1 + 1 + 1) ? ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "basenew", & self.basenew) ?
            ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "pattern", & self.pattern) ?
            ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "enumval", & self.enumval) ?
            ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "strval", & self.strval) ? ;
            _serde :: ser :: SerializeStruct :: end(__serde_state)
        }
    }
};

#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications,
clippy :: absolute_paths,)] const _ : () =
{
    #[allow(unused_extern_crates, clippy :: useless_attribute)] extern crate
    serde as _serde; #[automatically_derived] impl < 'de > _serde ::
    Deserialize < 'de > for DeriveStruct
    {
        fn deserialize < __D > (__deserializer : __D) -> _serde :: __private
        :: Result < Self, __D :: Error > where __D : _serde :: Deserializer <
        'de > ,
        {
            #[allow(non_camel_case_types)] #[doc(hidden)] enum __Field
            { __field0, __field1, __field2, __field3, __ignore, }
            #[doc(hidden)] struct __FieldVisitor; #[automatically_derived]
            impl < 'de > _serde :: de :: Visitor < 'de > for __FieldVisitor
            {
                type Value = __Field; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "field identifier")
                } fn visit_u64 < __E > (self, __value : u64) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        0u64 => _serde :: __private :: Ok(__Field :: __field0), 1u64
                        => _serde :: __private :: Ok(__Field :: __field1), 2u64 =>
                        _serde :: __private :: Ok(__Field :: __field2), 3u64 =>
                        _serde :: __private :: Ok(__Field :: __field3), _ => _serde
                        :: __private :: Ok(__Field :: __ignore),
                    }
                } fn visit_str < __E > (self, __value : & str) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        "basenew" => _serde :: __private :: Ok(__Field :: __field0),
                        "pattern" => _serde :: __private :: Ok(__Field :: __field1),
                        "enumval" => _serde :: __private :: Ok(__Field :: __field2),
                        "strval" => _serde :: __private :: Ok(__Field :: __field3),
                        _ => { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                } fn visit_bytes < __E > (self, __value : & [u8]) -> _serde ::
                __private :: Result < Self :: Value, __E > where __E : _serde
                :: de :: Error,
                {
                    match __value
                    {
                        b"basenew" => _serde :: __private ::
                        Ok(__Field :: __field0), b"pattern" => _serde :: __private
                        :: Ok(__Field :: __field1), b"enumval" => _serde ::
                        __private :: Ok(__Field :: __field2), b"strval" => _serde ::
                        __private :: Ok(__Field :: __field3), _ =>
                        { _serde :: __private :: Ok(__Field :: __ignore) }
                    }
                }
            } #[automatically_derived] impl < 'de > _serde :: Deserialize <
            'de > for __Field
            {
                #[inline] fn deserialize < __D > (__deserializer : __D) ->
                _serde :: __private :: Result < Self, __D :: Error > where __D
                : _serde :: Deserializer < 'de > ,
                {
                    _serde :: Deserializer ::
                    deserialize_identifier(__deserializer, __FieldVisitor)
                }
            } #[doc(hidden)] struct __Visitor < 'de >
            {
                marker : _serde :: __private :: PhantomData < DeriveStruct > ,
                lifetime : _serde :: __private :: PhantomData < & 'de () > ,
            } #[automatically_derived] impl < 'de > _serde :: de :: Visitor <
            'de > for __Visitor < 'de >
            {
                type Value = DeriveStruct; fn
                expecting(& self, __formatter : & mut _serde :: __private ::
                Formatter) -> _serde :: __private :: fmt :: Result
                {
                    _serde :: __private :: Formatter ::
                    write_str(__formatter, "struct DeriveStruct")
                } #[inline] fn visit_seq < __A > (self, mut __seq : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: SeqAccess < 'de > ,
                {
                    let __field0 = match _serde :: de :: SeqAccess ::
                    next_element :: < Vec < BaseStruct > > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(0usize, &
                        "struct DeriveStruct with 4 elements")),
                    }; let __field1 = match _serde :: de :: SeqAccess ::
                    next_element :: < NoPatternStruct > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(1usize, &
                        "struct DeriveStruct with 4 elements")),
                    }; let __field2 = match _serde :: de :: SeqAccess ::
                    next_element :: < DeriveEnum > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(2usize, &
                        "struct DeriveStruct with 4 elements")),
                    }; let __field3 = match _serde :: de :: SeqAccess ::
                    next_element :: < NAsn1OctData > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(3usize, &
                        "struct DeriveStruct with 4 elements")),
                    }; _serde :: __private ::
                    Ok(DeriveStruct
                    {
                        basenew : __field0, pattern : __field1, enumval : __field2,
                        strval : __field3
                    })
                } #[inline] fn visit_map < __A > (self, mut __map : __A) ->
                _serde :: __private :: Result < Self :: Value, __A :: Error >
                where __A : _serde :: de :: MapAccess < 'de > ,
                {
                    let mut __field0 : _serde :: __private :: Option < Vec <
                    BaseStruct > > = _serde :: __private :: None; let mut
                    __field1 : _serde :: __private :: Option < NoPatternStruct >
                    = _serde :: __private :: None; let mut __field2 : _serde ::
                    __private :: Option < DeriveEnum > = _serde :: __private ::
                    None; let mut __field3 : _serde :: __private :: Option <
                    NAsn1OctData > = _serde :: __private :: None; while let
                    _serde :: __private :: Some(__key) = _serde :: de ::
                    MapAccess :: next_key :: < __Field > (& mut __map) ?
                    {
                        match __key
                        {
                            __Field :: __field0 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field0)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("basenew"));
                                } __field0 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < Vec <
                                BaseStruct > > (& mut __map) ?);
                            } __Field :: __field1 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field1)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("pattern"));
                                } __field1 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: <
                                NoPatternStruct > (& mut __map) ?);
                            } __Field :: __field2 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field2)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("enumval"));
                                } __field2 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: < DeriveEnum
                                > (& mut __map) ?);
                            } __Field :: __field3 =>
                            {
                                if _serde :: __private :: Option :: is_some(& __field3)
                                {
                                    return _serde :: __private ::
                                    Err(< __A :: Error as _serde :: de :: Error > ::
                                    duplicate_field("strval"));
                                } __field3 = _serde :: __private ::
                                Some(_serde :: de :: MapAccess :: next_value :: <
                                NAsn1OctData > (& mut __map) ?);
                            } _ =>
                            {
                                let _ = _serde :: de :: MapAccess :: next_value :: < _serde
                                :: de :: IgnoredAny > (& mut __map) ? ;
                            }
                        }
                    } let __field0 = match __field0
                    {
                        _serde :: __private :: Some(__field0) => __field0, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("basenew") ? ,
                    }; let __field1 = match __field1
                    {
                        _serde :: __private :: Some(__field1) => __field1, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("pattern") ? ,
                    }; let __field2 = match __field2
                    {
                        _serde :: __private :: Some(__field2) => __field2, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("enumval") ? ,
                    }; let __field3 = match __field3
                    {
                        _serde :: __private :: Some(__field3) => __field3, _serde ::
                        __private :: None => _serde :: __private :: de ::
                        missing_field("strval") ? ,
                    }; _serde :: __private ::
                    Ok(DeriveStruct
                    {
                        basenew : __field0, pattern : __field1, enumval : __field2,
                        strval : __field3
                    })
                }
            } #[doc(hidden)] const FIELDS : & 'static [& 'static str] = &
            ["basenew", "pattern", "enumval", "strval"]; _serde ::
            Deserializer ::
            deserialize_struct(__deserializer, "DeriveStruct", FIELDS,
            __Visitor
            {
                marker : _serde :: __private :: PhantomData :: < DeriveStruct
                > , lifetime : _serde :: __private :: PhantomData,
            })
        }
    }
};
