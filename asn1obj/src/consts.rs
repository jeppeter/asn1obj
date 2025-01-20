
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
pub const ASN1_PRINTABLE_FLAG :u8 = 0x13;
pub const ASN1_T61STRING_FLAG :u8 = 0x14;
pub const ASN1_PRINTABLE2_FLAG :u8 = 0x16;
pub const ASN1_UTCTIME_FLAG : u8 = 0x17;
pub const ASN1_BMPSTRING_FLAG :u8 = 0x1e;
pub const ASN1_GENERALTIME_FLAG : u8 = 0x18;
pub const ASN1_IMP_FLAG_MASK :u8 = 0x80;
pub const ASN1_SEQ_MASK :u8 = 0x30;
pub const ASN1_SET_MASK :u8 = 0x31;
pub const ASN1_IMP_SET_MASK :u8 = 0xa0;
pub const ASN1_IMP_FILTER_MASK :u8 = 0xe0;

pub const ASN1_TIME_DEFAULT_STR :&str = "1970-01-01 00:00";
pub const ASN1_OBJECT_DEFAULT_STR :&str = "1.1.1";


pub const ASN1_JSON_TAG :&str = "tag";
pub const ASN1_JSON_CONTENT :&str = "content";
pub const ASN1_JSON_PRINTABLE_STRING :&str = "printablestring";
pub const ASN1_JSON_IA5STRING :&str = "ia5string";
pub const ASN1_JSON_INNER_FLAG :&str = "_flag";
pub const ASN1_JSON_BITDATA :&str = "bitdata";
pub const ASN1_JSON_TIME :&str = "time";
pub const ASN1_JSON_DUMMY :&str = "dummy";
pub const ASN1_JSON_FLAG :&str = "flag";

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

