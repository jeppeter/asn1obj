
pub const ASN1_PRIMITIVE_TAG : u8 = 0x1f;
pub const ASN1_CONSTRUCTED : u8 = 0x20;

pub const ASN1_BOOLEAN_FLAG : u8 = 0x1;
pub const ASN1_INTEGER_FLAG : u8 = 0x2;
pub const ASN1_BIT_STRING_FLAG : u8 = 0x3;
pub const ASN1_OCT_STRING_FLAG : u8 = 0x4;
pub const ASN1_NULL_FLAG :u8 = 0x5;
pub const ASN1_OBJECT_FLAG :u8 = 0x6;
pub const ASN1_ENUMERATED_FLAG :u8 = 0xa;
pub const ASN1_UTF8STRING_FLAG :u8 = 0xc;
pub const ASN1_IMP_FLAG_MASK :u8 = 0x80;

pub const ASN1_SET_OF_FLAG :u8 = 0xa0;



pub const ASN1_MAX_INT :u64 = 0xffffffff;
pub const ASN1_MAX_LONG :u64 = 0xffffffff;
pub const ASN1_MAX_INT_1 :u64 = 0xff;
pub const ASN1_MAX_INT_MASK_1 :u64 = 0xffffff00;
pub const ASN1_MAX_INT_2 :u64 = 0xffff;
pub const ASN1_MAX_INT_MASK_2 :u64 = 0xffff0000;
pub const ASN1_MAX_INT_3 :u64 = 0xffffff;
pub const ASN1_MAX_INT_MASK_3 :u64 = 0xff000000;
pub const ASN1_MAX_INT_4 :u64 = 0xffffffff;
pub const ASN1_MAX_INT_MASK_4 :u64 = 0x00000000;
pub const ASN1_MAX_INT_5 :u64 = 0xffffffffff;
pub const ASN1_MAX_INT_MASK_5 :u64 = 0x0000000000;
pub const ASN1_MAX_LL :u64 = 0xffffffffffffffff;

pub const ASN1_MAX_INT_NEG_1 :u64 = 0x80;
pub const ASN1_MAX_INT_NEG_2 :u64 = 0x8000;
pub const ASN1_MAX_INT_NEG_3 :u64 = 0x800000;
pub const ASN1_MAX_INT_NEG_4 :u64 = 0x80000000;
pub const ASN1_MAX_INT_NEG_5 :u64 = 0x8000000000;
pub const ASN1_MAX_INT_NEG_6 :u64 = 0x800000000000;
pub const ASN1_MAX_INT_NEG_7 :u64 = 0x80000000000000;
pub const ASN1_MAX_INT_NEG_8 :u64 = 0x8000000000000000;

