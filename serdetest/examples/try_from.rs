
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
            _serde :: Serialize ::
            serialize(& _serde :: __private :: Into :: < i32 > ::
            into(_serde :: __private :: Clone :: clone(self)), __serializer)
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
            _serde :: __private :: Result ::
            and_then(< i32 as _serde :: Deserialize > ::
            deserialize(__deserializer), | v | _serde :: __private :: TryFrom
            :: try_from(v).map_err(_serde :: de :: Error :: custom))
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
            + 1 + 1) ? ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "basenew", & self.basenew) ?
            ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "pattern", & self.pattern) ?
            ; _serde :: ser :: SerializeStruct ::
            serialize_field(& mut __serde_state, "enumval", & self.enumval) ?
            ; _serde :: ser :: SerializeStruct :: end(__serde_state)
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
            { __field0, __field1, __field2, __ignore, } #[doc(hidden)] struct
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
                        => _serde :: __private :: Ok(__Field :: __field1), 2u64 =>
                        _serde :: __private :: Ok(__Field :: __field2), _ => _serde
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
                        __private :: Ok(__Field :: __field2), _ =>
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
                        "struct DeriveStruct with 3 elements")),
                    }; let __field1 = match _serde :: de :: SeqAccess ::
                    next_element :: < NoPatternStruct > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(1usize, &
                        "struct DeriveStruct with 3 elements")),
                    }; let __field2 = match _serde :: de :: SeqAccess ::
                    next_element :: < DeriveEnum > (& mut __seq) ?
                    {
                        _serde :: __private :: Some(__value) => __value, _serde ::
                        __private :: None => return _serde :: __private ::
                        Err(_serde :: de :: Error ::
                        invalid_length(2usize, &
                        "struct DeriveStruct with 3 elements")),
                    }; _serde :: __private ::
                    Ok(DeriveStruct
                    {
                        basenew : __field0, pattern : __field1, enumval : __field2
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
                    None; while let _serde :: __private :: Some(__key) = _serde
                    :: de :: MapAccess :: next_key :: < __Field > (& mut __map)
                    ?
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
                    }; _serde :: __private ::
                    Ok(DeriveStruct
                    {
                        basenew : __field0, pattern : __field1, enumval : __field2
                    })
                }
            } #[doc(hidden)] const FIELDS : & 'static [& 'static str] = &
            ["basenew", "pattern", "enumval"]; _serde :: Deserializer ::
            deserialize_struct(__deserializer, "DeriveStruct", FIELDS,
            __Visitor
            {
                marker : _serde :: __private :: PhantomData :: < DeriveStruct
                > , lifetime : _serde :: __private :: PhantomData,
            })
        }
    }
};
