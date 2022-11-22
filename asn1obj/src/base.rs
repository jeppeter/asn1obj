

use std::error::Error;
use chrono::{Utc,DateTime,Datelike,Timelike,Duration};
use chrono::prelude::*;
use crate::asn1impl::{Asn1Op};
//use crate::consts::{ASN1_PRIMITIVE_TAG,ASN1_CONSTRUCTED,ASN1_INTEGER_FLAG,ASN1_BOOLEAN_FLAG,ASN1_MAX_INT,ASN1_MAX_LONG,ASN1_MAX_INT_1,ASN1_MAX_INT_2,ASN1_MAX_INT_3,ASN1_MAX_INT_4,ASN1_MAX_INT_NEG_1,ASN1_MAX_INT_NEG_2,ASN1_MAX_INT_NEG_3,ASN1_MAX_INT_NEG_4,ASN1_MAX_INT_NEG_5,ASN1_MAX_INT_5,ASN1_BIT_STRING_FLAG,ASN1_OCT_STRING_FLAG,ASN1_NULL_FLAG,ASN1_OBJECT_FLAG,ASN1_ENUMERATED_FLAG,ASN1_UTF8STRING_FLAG,ASN1_PRINTABLE_FLAG,ASN1_UTCTIME_FLAG,ASN1_GENERALTIME_FLAG,ASN1_TIME_DEFAULT_STR,ASN1_OBJECT_DEFAULT_STR,ASN1_PRINTABLE2_FLAG};
use crate::consts::*;
use crate::strop::{asn1_format_line};
use crate::{asn1obj_error_class,asn1obj_new_error};

use std::io::{Write};

use crate::{asn1obj_log_trace,asn1obj_debug_buffer_trace,asn1obj_format_buffer_log};
use crate::logger::{asn1obj_debug_out,asn1obj_log_get_timestamp};

use bytes::{BytesMut,BufMut};
use regex::Regex;
use serde_json;

use std::str::FromStr;
use std::ops::Shr;
use num_bigint::{BigUint};
use num_traits::{Zero};


asn1obj_error_class!{Asn1ObjBaseError}


pub fn asn1obj_extract_header(code :&[u8]) -> Result<(u64,usize,usize),Box<dyn Error>> {
    let flag :u64;
    let mut totallen :usize = 0;
    let mut i :u64;
    let mut llen :usize = 0;
    let inf :i32;
    let ret :u8;
    if code.len() < 2 {
        asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
    }

    i = (code[llen]  & ASN1_PRIMITIVE_TAG) as u64;
    ret = code[llen] & ASN1_CONSTRUCTED;
    if i == ASN1_PRIMITIVE_TAG  as u64 {
        llen += 1;
        if code.len() <= llen {
            asn1obj_new_error!{Asn1ObjBaseError,"expose [{}] len", code.len()}
        }
        i = 0;
        while (code[llen] & 0x80) != 0x0 {
            i <<= 7;
            i += (code[llen] & 0x7f) as u64;
            llen += 1;
            if code.len() <= llen {
                asn1obj_new_error!{Asn1ObjBaseError,"expose [{}] len", code.len()}      
            }
            if i > (ASN1_MAX_INT  >> 7) {
                asn1obj_new_error!{Asn1ObjBaseError,"[0x{:08x}] expose [0x{:08x}]", i, ASN1_MAX_INT}
            }
        }
        i <<= 7;
        i += (code[llen] & 0x7f) as u64;
        llen += 1;
        flag = i;
    } else {
        flag = code[0] as u64;
        llen += 1;
    }

    if code.len() <= llen {
        asn1obj_new_error!{Asn1ObjBaseError,"expose [{}] len", code.len()}
    }

    if code[llen] == 0x80 {
        inf = 1;
        llen += 1;
    } else {
        inf = 0;
        i = (code[llen] & 0x7f) as u64;
        if (code[llen] & 0x80) != 0 {

            if code.len() <= (llen + (i as usize)) {
                asn1obj_new_error!{Asn1ObjBaseError,"llen [0x{:08x}] + [0x{:08x}] >= [0x{:08x}]", llen, i, code.len()}
            }
            /*skip this one*/
            i -= 1;
            llen += 1;
            while i > 0 && code[llen] == 0x0 {
                llen += 1;
                i -= 1;
            }

            if i > 4 {
                asn1obj_new_error!{Asn1ObjBaseError,"left [{}] > 4", i}
            }
            totallen = 0;
            while i > 0 {
                totallen <<= 8;
                totallen += (code[llen]) as usize;
                asn1obj_log_trace!("code[{}]=[0x{:02x}]",llen,code[llen]);
                llen += 1;
                i -= 1;
            }
            /*to add last one*/
            totallen <<= 8;
            totallen += (code[llen]) as usize;
            llen += 1;

            if totallen > ASN1_MAX_LONG as usize {
                asn1obj_new_error!{Asn1ObjBaseError,"totallen [0x{:x}] > [0x{:x}]", totallen, ASN1_MAX_LONG}
            }
        } else {
            totallen = i as usize;
            llen += 1;
        }
    }

    if inf != 0 && (ret & ASN1_CONSTRUCTED) == 0 {
        asn1obj_new_error!{Asn1ObjBaseError,"inf [{}] ASN1_CONSTRUCTED not", inf}
    }
    asn1obj_log_trace!("flag [0x{:02x}] llen [0x{:x}] totallen [0x{:x}]", flag, llen,totallen);
    Ok((flag,llen,totallen))
}

pub fn asn1obj_format_header(tag :u64, length :u64) -> Vec<u8> {
    let mut retv :Vec<u8> = Vec::new();
    if (tag & 0xff) == tag {
        retv.push((tag & 0xff) as u8);
    } else {
        retv.push(0x0);
    }
    if length < ASN1_MAX_INT_NEG_1 {
        retv.push((length & 0xff) as u8);
    } else if length <= ASN1_MAX_INT_1 {
        retv.push(0x81);
        retv.push((length & 0xff) as u8);       
    } else if length <= ASN1_MAX_INT_2 {
        retv.push(0x82);
        retv.push(((length >> 8) & 0xff) as u8);
        retv.push((length & 0xff) as u8);
    } else if length <= ASN1_MAX_INT_3 {
        retv.push(0x83);
        retv.push(((length >> 16) & 0xff) as u8);
        retv.push(((length >> 8) & 0xff) as u8);
        retv.push(((length >> 0) & 0xff) as u8);
    } else if length <= ASN1_MAX_INT_4 {
        retv.push(0x84);
        retv.push(((length >> 24) & 0xff) as u8);
        retv.push(((length >> 16) & 0xff) as u8);
        retv.push(((length >> 8) & 0xff) as u8);
        retv.push(((length >> 0) & 0xff) as u8);
    } else {
        panic!("can not exceed {} ",length);
    }
    return retv;
}

#[derive(Clone)]
pub struct Asn1Any {
    pub content :Vec<u8>,
    pub tag : u64,
}

impl Asn1Any {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut setjson :serde_json::value::Value = serde_json::from_str("{}").unwrap();
        setjson[ASN1_JSON_CONTENT] = serde_json::json!([]);
        for i in 0..self.content.len() {
            setjson[ASN1_JSON_CONTENT][i] = serde_json::json!(self.content[i]);
        }
        setjson[ASN1_JSON_TAG] = serde_json::json!(self.tag);
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.content = Vec::new();
            self.tag = ASN1_NULL_FLAG as u64;
            return Ok(0);
        }
        let vmap = ores.unwrap();
        let ores = vmap.get(ASN1_JSON_TAG);
        if ores.is_none() {
            asn1obj_new_error!{Asn1ObjBaseError,"no {} found in {}", ASN1_JSON_TAG,key}
        }
        let ores2 = vmap.get(ASN1_JSON_CONTENT);
        if ores2.is_none() {
            asn1obj_new_error!{Asn1ObjBaseError,"no {} found in {}",ASN1_JSON_CONTENT,key}
        }
        let tagv = ores.unwrap();
        let conv = ores2.unwrap();
        if !tagv.is_i64() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not i64", ASN1_JSON_TAG}
        }
        if !conv.is_array() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not array",ASN1_JSON_CONTENT}
        }
        let c = tagv.as_i64().unwrap();
        self.tag = c as u64;
        self.content = Vec::new();
        for v in conv.as_array().unwrap().iter() {
            let c = v.as_u64().unwrap();
            self.content.push(c as u8);
        }
        return Ok(1);
    }
}

impl Asn1Op for Asn1Any {
    fn init_asn1() -> Self {
        Asn1Any {
            tag : 0,
            content : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        self.tag = flag ;


        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        self.content = Vec::new();
        for i in 0..totallen{
            self.content.push(code[hdrlen+i]);
        }
        asn1obj_debug_buffer_trace!(code.as_ptr(), code.len(), "deocde any");
        retv= hdrlen + totallen;
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8>;
        retv = asn1obj_format_header(self.tag , self.content.len() as u64);
        for i in 0..self.content.len() {
            retv.push(self.content[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let mut s = asn1_format_line(tab,&(format!("{}: ASN1_ANY tag 0x{:02x} {} ", name, self.tag, self.content.len())));
        let mut idx :usize;
        let mut lastidx :usize;
        let mut curs :String;
        idx = 0;
        lastidx = 0;
        curs = format!("0x{:08x}:",idx);
        while idx < self.content.len() {
            if (idx % 16) == 0 && idx > 0 {
                curs.push_str(&format!("    "));
                while lastidx < idx {
                    if (self.content[lastidx] >= 0x20) && (self.content[lastidx] <= 0x7e) {
                        curs.push(self.content[lastidx] as char);
                    } else {
                        curs.push_str(".");
                    }
                    lastidx += 1;
                }
                s.push_str(&asn1_format_line(tab + 1,&format!("{}",curs)));
                curs = format!("0x{:08x}:",idx);
            }
            curs.push_str(&format!(" 0x{:02x}",self.content[idx]));
            idx += 1;
        }

        if idx != lastidx {
            while (idx % 16) != 0 {
                curs.push_str("     ");
                idx += 1;
            }
            curs.push_str("    ");
            while lastidx != self.content.len() {
                if self.content[lastidx] >= 0x20 && self.content[lastidx] <= 0x7e {
                    curs.push(self.content[lastidx] as char);
                } else {
                    curs.push_str(".");
                }
                lastidx += 1;
            }
            s.push_str(&asn1_format_line(tab + 1, &(format!("{}",curs))));
        }

        iowriter.write(s.as_bytes())?;
        Ok(())
    }   
}

#[derive(Clone)]
pub struct Asn1Integer {
    pub val :i64,
    data :Vec<u8>,
}


impl Asn1Integer {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = 0;
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_i64() && !vmap.is_string() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or i64",key}
        }
        if vmap.is_i64() {
            let c = vmap.as_i64().unwrap();
            self.val = c ;
        } else if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            match c.parse::<i64>() {
                Ok(fi) => {
                    self.val = fi;
                },
                Err(e) => {
                    asn1obj_new_error!{Asn1ObjBaseError,"{} val {} error {:?}", key,c,e}
                }
            }
        }
        return Ok(1);
    }
}


impl Asn1Op for Asn1Integer {
    fn init_asn1() -> Self {
        Asn1Integer {
            val : 0,
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        let mut ival :i64;
        let mut neg :bool = false;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_INTEGER_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_INTEGER_FLAG [0x{:02x}]", flag,ASN1_INTEGER_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen < 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"need 1 length"}
        }
        if (code[hdrlen] & 0x80) != 0 {
            neg = true;
        }



        if neg {
            let mut uval :u64;
            uval = 0;
            for i in 0..totallen {
                uval <<= 8;
                uval += (code[hdrlen+i]) as u64;
                asn1obj_log_trace!("[0x{:x}]", uval);
            }

            if uval <= ASN1_MAX_INT_1 {
                ival = (ASN1_MAX_INT_1 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_2 {
                ival = (ASN1_MAX_INT_2 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_3 {
                ival = (ASN1_MAX_INT_3 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_4 {
                ival = (ASN1_MAX_INT_4 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_5 {
                ival = (ASN1_MAX_INT_5 - uval + 1) as i64;
            } else {
                asn1obj_new_error!{Asn1ObjBaseError,"invalid uval [0x{:x}]", uval}
            }

            asn1obj_log_trace!("ival {}",ival);
            ival = -ival;
        } else {                
            ival = 0;
            for i in 0..totallen {
                ival <<= 8;
                ival += (code[hdrlen+i]) as i64;
            }
        }
        self.val = ival;
        self.data = Vec::new();
        for i in 0..(hdrlen + totallen) {
            self.data.push(code[i]);
        }
        asn1obj_debug_buffer_trace!(self.data.as_ptr(),self.data.len(),"Asn1Integer {}", self.val);
        retv= hdrlen + totallen;
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        retv.push(ASN1_INTEGER_FLAG);
        retv.push(8);
        if self.val >= 0 {
            if self.val < ASN1_MAX_INT_NEG_1 as i64 {
                retv.push((self.val & 0xff) as u8);
                retv[1] = 1;
            } else if self.val < ASN1_MAX_INT_NEG_2 as i64 {
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 2;
            } else if self.val < ASN1_MAX_INT_NEG_3 as i64 {
                retv.push(((self.val >> 16) & 0xff) as u8);
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 3;
            } else if self.val < ASN1_MAX_INT_NEG_4 as i64 {
                retv.push(((self.val >> 24) & 0xff) as u8);
                retv.push(((self.val >> 16) & 0xff) as u8);
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 4;
            } else if self.val < ASN1_MAX_INT_NEG_5 as i64 {
                retv.push(((self.val >> 32) & 0xff) as u8);
                retv.push(((self.val >> 24) & 0xff) as u8);
                retv.push(((self.val >> 16) & 0xff) as u8);
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 5;
            } else {
                asn1obj_new_error!{Asn1ObjBaseError,"value [0x{:x}] > [0x{:x}]", self.val, ASN1_MAX_INT_NEG_4}
            }
        } else {
            let ival :i64 = - self.val;
            let mut uval :u64 = self.val as u64;
            uval = uval ^ 0;
            asn1obj_log_trace!("ival [{}] uval [{}]",ival,uval);
            if ival <= ASN1_MAX_INT_NEG_1 as i64 {
                retv.push((uval & 0xff) as u8);
                retv[1] = 1;
            } else if ival <= ASN1_MAX_INT_NEG_2 as i64 {
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 2;
            } else if ival <= ASN1_MAX_INT_NEG_3 as i64 {
                retv.push(((uval >> 16) & 0xff) as u8);
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 3;
            } else if ival <= ASN1_MAX_INT_NEG_4 as i64 {
                retv.push(((uval >> 24) & 0xff) as u8);
                retv.push(((uval >> 16) & 0xff) as u8);
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 4;
            } else if ival <= ASN1_MAX_INT_NEG_5 as i64 {
                retv.push(((uval >> 32) & 0xff ) as u8);
                retv.push(((uval >> 24) & 0xff) as u8);
                retv.push(((uval >> 16) & 0xff) as u8);
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 5;
            } else {
                asn1obj_new_error!{Asn1ObjBaseError,"neg value [0x{:x}] >= [0x{:x}]", uval, ASN1_MAX_INT_NEG_4}
            }
            asn1obj_log_trace!("retv {:?}", retv);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_INTEGER {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Asn1Boolean {
    pub val :bool,
    data :Vec<u8>,
}

impl Asn1Boolean {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = false;
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_boolean()  {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid bool",key}
        }
        let c = vmap.as_bool().unwrap();
        self.val = c ;
        return Ok(1);
    }
}

impl Asn1Op for Asn1Boolean {
    fn init_asn1() -> Self {
        Asn1Boolean {
            val : false,
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_BOOLEAN_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_BOOLEAN_FLAG [0x{:02x}]", flag,ASN1_BOOLEAN_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen != 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] != 1", totallen}
        }

        if code[hdrlen]  != 0 {
            self.val = true;
        } else {
            self.val = false;
        }

        asn1obj_log_trace!("Asn1Boolean {}",self.val);

        retv = hdrlen + totallen;
        self.data = Vec::new();
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        retv.push(ASN1_BOOLEAN_FLAG);
        retv.push(1);
        if self.val  {
            retv.push(0xff);
        } else {
            retv.push(0)
        }       
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_BOOLEAN {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Asn1BitString {
    pub val :String,
    data :Vec<u8>,
}

impl Asn1BitString {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = "".to_string();
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_string()  {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string",key}
        }
        let c = vmap.as_str().unwrap();
        self.val = format!("{}",c) ;
        return Ok(1);
    }
}


impl Asn1Op for Asn1BitString {
    fn init_asn1() -> Self {
        Asn1BitString {
            val : "".to_string(),
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_BIT_STRING_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_BIT_STRING_FLAG [0x{:02x}]", flag,ASN1_BIT_STRING_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen < 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] < 1", totallen}
        }

        let mut retm = BytesMut::with_capacity(totallen - 1);
        for i in 1..totallen {
            retm.put_u8(code[hdrlen + i]);
        }
        let a = retm.freeze();
        self.val = String::from_utf8_lossy(&a).to_string();
        asn1obj_log_trace!("Asn1BitString [{}]",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let vcode = self.val.as_bytes();
        let llen :u64 = (vcode.len() + 1) as u64;
        let mut retv :Vec<u8>;
        let bits :u8;
        let mut idx :usize;

        if vcode.len() == 0 {
            asn1obj_new_error!{Asn1ObjBaseError,"data [0] not valid"}
        }

        retv = asn1obj_format_header(ASN1_BIT_STRING_FLAG as u64,llen);
        idx = vcode.len() - 1;

        while idx > 0 {
            if vcode[idx] != 0 {
                break;
            }
            idx -= 1;
        }

        if vcode[idx] == 0  || (vcode[idx] & 0x1) != 0{
            bits = 0;
        } else if (vcode[idx] & 0x2)  != 0 {
            bits = 1;
        } else if (vcode[idx] & 0x4) != 0 {
            bits = 2;
        } else if (vcode[idx] & 0x8) != 0 {
            bits = 3;
        } else if (vcode[idx] & 0x10) != 0 {
            bits = 4;
        } else if (vcode[idx] & 0x20) != 0 {
            bits = 5;
        } else if (vcode[idx] & 0x40) != 0 {
            bits = 6;
        } else if (vcode[idx] & 0x80) != 0 {
            bits = 7;
        } else {
            bits = 0;
        }

        retv.push(bits);
        for i in 0..vcode.len() {
            retv.push(vcode[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_BIT_STRING {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Asn1BitData {
    pub data :Vec<u8>,
}

impl Asn1BitData {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut cs :String = "".to_string();
        let mut idx :i32 = 0;
        cs.push_str("[");
        for v in self.data.iter() {
            if idx > 0 {
                cs.push_str(",");
            }
            cs.push_str(&format!("{}",v));
            idx += 1;
        }
        cs.push_str("]");
        let setjson = serde_json::from_str(&cs).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_string() && !vmap.is_array()  {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or array",key}
        }
        self.data = Vec::new();
        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            for v in c.as_bytes().iter() {
                self.data.push((*v) as u8);
            }

        } else if vmap.is_array() {
            let c = vmap.as_array().unwrap();
            for v in c.iter() {
                if !v.is_i64() {
                    asn1obj_new_error!{Asn1ObjBaseError,"{} invalid element {:?}",key,c}
                }
                self.data.push(v.as_u64().unwrap() as u8);
            }
        }
        return Ok(1);
    }
}


impl Asn1Op for Asn1BitData {
    fn init_asn1() -> Self {
        Asn1BitData {
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_BIT_STRING_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_BIT_STRING_FLAG [0x{:02x}]", flag,ASN1_BIT_STRING_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen < 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] < 1", totallen}
        }
        asn1obj_log_trace!("totallen [{}]",totallen);

        self.data = Vec::new();
        for i in 1..totallen {
            self.data.push(code[hdrlen + i]);
        }
        asn1obj_debug_buffer_trace!(self.data.as_ptr(), self.data.len(),"Asn1BitData");
        retv = hdrlen + totallen;
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let llen :u64 = (self.data.len() + 1) as u64;
        let mut retv :Vec<u8>;
        let bits :u8;
        let mut idx :usize;

        retv = asn1obj_format_header(ASN1_BIT_STRING_FLAG as u64,llen);
        if self.data.len() > 0 {
            idx = self.data.len() -1;


            while idx > 0 {
                if self.data[idx] != 0 {
                    break;
                }
                idx -= 1;
            }

            if self.data[idx] == 0  || (self.data[idx] & 0x1) != 0{
                bits = 0;
            } else if (self.data[idx] & 0x2)  != 0 {
                bits = 1;
            } else if (self.data[idx] & 0x4) != 0 {
                bits = 2;
            } else if (self.data[idx] & 0x8) != 0 {
                bits = 3;
            } else if (self.data[idx] & 0x10) != 0 {
                bits = 4;
            } else if (self.data[idx] & 0x20) != 0 {
                bits = 5;
            } else if (self.data[idx] & 0x40) != 0 {
                bits = 6;
            } else if (self.data[idx] & 0x80) != 0 {
                bits = 7;
            } else {
                bits = 0;
            }           
        } else {
            bits = 0;
        }

        retv.push(bits);
        for i in 0..self.data.len() {
            retv.push(self.data[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let mut s = asn1_format_line(tab,&(format!("{}: ASN1_BIT_DATA len[0x{:x}:{}]", name,self.data.len(),self.data.len())));
        let mut idx :usize = 0;
        let mut lasti :usize = 0;

        while idx < self.data.len() {
            if (idx % 16) == 0 {
                if idx > 0 {
                    s.push_str("    ");
                    while lasti != idx {
                        if self.data[lasti] >= 0x20 && self.data[lasti] <= 0x7e {
                            s.push(self.data[lasti] as char);
                        } else {
                            s.push_str(".");
                        }
                        lasti += 1;
                    }
                    s.push_str("\n");
                }
                for _ in 0..(tab + 1) {
                    s.push_str("    ");
                }

            }
            if idx != lasti {
                s.push_str(":");
            }
            s.push_str(&format!("{:02x}",self.data[idx]));
            idx += 1;
        }
        if lasti != idx {
            while (idx % 16) != 0 {
                s.push_str("   ");
                idx += 1;
            }
            s.push_str("    ");
            while lasti < self.data.len() {
                if self.data[lasti] >= 0x20 && self.data[lasti] <= 0x7e {
                    s.push(self.data[lasti] as char);
                } else {
                    s.push_str(".");
                }
                lasti += 1;
            }
        }
        if idx > 0 {
            s.push_str("\n");
        }

        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct Asn1OctString {
    pub val :String,
    data :Vec<u8>,
}

impl Asn1OctString {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_string() && !vmap.is_array()  {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or array",key}
        }
        self.val = "".to_string();
        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            self.val = format!("{}",c);
        } else if vmap.is_array() {
            let c = vmap.as_array().unwrap();
            let mut retm = BytesMut::with_capacity(c.len());
            for v in c.iter() {
                if !v.is_i64() {
                    asn1obj_new_error!{Asn1ObjBaseError,"{} invalid element {:?}",key,c}
                }
                retm.put_u8(v.as_u64().unwrap() as u8);
            }
            let a = retm.freeze();
            self.val = String::from_utf8_lossy(&a).to_string();
        }
        return Ok(1);
    }
}

impl Asn1Op for Asn1OctString {
    fn init_asn1() -> Self {
        Asn1OctString {
            val : "".to_string(),
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_OCT_STRING_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_OCT_STRING_FLAG [0x{:02x}]", flag,ASN1_OCT_STRING_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }


        let mut retm = BytesMut::with_capacity(totallen);
        for i in 0..totallen {
            retm.put_u8(code[hdrlen + i]);
        }
        let a = retm.freeze();
        self.val = String::from_utf8_lossy(&a).to_string();
        asn1obj_log_trace!("Asn1OctString [{}]",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let vcode = self.val.as_bytes();
        let llen :u64 = (vcode.len() ) as u64;
        let mut retv :Vec<u8>;

        retv = asn1obj_format_header(ASN1_OCT_STRING_FLAG as u64,llen);

        for i in 0..vcode.len() {
            retv.push(vcode[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_OCT_STRING {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Asn1OctData {
    pub data :Vec<u8>,
}

impl Asn1OctData {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut cs :String = "[".to_string();
        let mut idx :i32 = 0;
        for v in self.data.iter() {
            if idx > 0 {
                cs.push_str(",");
            }
            cs.push_str(&format!("{}",v));
            idx += 1;
        }
        cs.push_str("]");
        let setjson = serde_json::from_str(&cs).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_string() && !vmap.is_array()  {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or array",key}
        }
        self.data = Vec::new();
        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            for v in c.as_bytes().iter() {
                self.data.push(*v);
            }
        } else if vmap.is_array() {
            let c = vmap.as_array().unwrap();
            for v in c.iter() {
                if !v.is_i64() {
                    asn1obj_new_error!{Asn1ObjBaseError,"{} invalid element {:?}",key,c}
                }
                self.data.push(v.as_u64().unwrap() as u8);
            }
        }
        return Ok(1);
    }
}


impl Asn1Op for Asn1OctData {
    fn init_asn1() -> Self {
        Asn1OctData {
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_OCT_STRING_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_OCT_STRING_FLAG [0x{:02x}]", flag,ASN1_OCT_STRING_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        self.data = Vec::new();
        for i in 0..totallen {
            self.data.push(code[hdrlen+i]);
        }
        retv= hdrlen + totallen;

        asn1obj_debug_buffer_trace!(self.data.as_ptr(),self.data.len(), "Asn1OctData");
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let llen :u64 = (self.data.len() ) as u64;
        let mut retv :Vec<u8>;

        retv = asn1obj_format_header(ASN1_OCT_STRING_FLAG as u64,llen);

        for i in 0..self.data.len() {
            retv.push(self.data[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let mut s = asn1_format_line(tab,&(format!("{}: ASN1_OCT_DATA", name)));
        let mut idx :usize = 0;
        let mut lasti :usize = 0;
        while idx < self.data.len() {
            if (idx % 16) == 0 {
                if idx > 0 {
                    s.push_str("    ");
                    while lasti != idx {
                        if self.data[lasti] >= 0x20 && self.data[lasti] <= 0x7e {
                            s.push(self.data[lasti] as char);
                        } else {
                            s.push_str(".");
                        }
                        lasti += 1;
                    }
                    s.push_str("\n");
                }
                for _ in 0..(tab+1) {
                    s.push_str("    ");
                }
            }
            if lasti != idx {
                s.push_str(":");
            }
            s.push_str(&format!("{:02x}",self.data[idx]));
            idx += 1;
        }

        if lasti != idx {
            while (idx % 16) != 0 {
                s.push_str("   ");
                idx += 1;
            }
            s.push_str("    ");
            while lasti < self.data.len() {
                if self.data[lasti] >= 0x20 && self.data[lasti] <= 0x7e {
                    s.push(self.data[lasti] as char);
                } else {
                    s.push_str(".");
                }
                lasti += 1;                
            }
            s.push_str("\n");
        }
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct Asn1Null {
    data :Vec<u8>,
}

impl Asn1Null {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("null")).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_null() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid null",key}
        }
        self.data = Vec::new();
        return Ok(1);
    }
}

impl Asn1Op for Asn1Null {
    fn init_asn1() -> Self {
        Asn1Null {
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_NULL_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_NULL_FLAG [0x{:02x}]", flag,ASN1_NULL_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen != 0 {
            asn1obj_new_error!{Asn1ObjBaseError,"totallen [{}] != 0",totallen}
        }

        asn1obj_log_trace!("Asn1Null");
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let retv :Vec<u8>;
        retv = asn1obj_format_header(ASN1_NULL_FLAG as u64,0);
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_NULL", name)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

const ULONG_MAX :u64 = 0xffffffffffffffff;


#[derive(Clone)]
pub struct Asn1Object {
    val :String,
    data :Vec<u8>,
}

impl Asn1Object {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            let _ = self.set_value("1.1.1")?;
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_string() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string",key}
        }
        let c = vmap.as_str().unwrap();
        let _ = self.set_value(c)?;
        return Ok(1);
    }
}


impl Asn1Object {
    pub fn set_value(&mut self,val :&str) -> Result<String,Box<dyn Error>> {
        let restr = format!("^([0-9\\.]+)$");
        let oldstr :String;
        let vo = Regex::new(&restr);
        if vo.is_err() {
            let err = vo.err().unwrap();
            asn1obj_new_error!{Asn1ObjBaseError,"can parse [{}] error [{:?}]", restr,err}
        }
        let re = vo.unwrap();
        if !re.is_match(val) {
            asn1obj_new_error!{Asn1ObjBaseError,"[{}] not valid for [{}]", val, restr}
        }
        let sarr :Vec<&str> = val.split(".").collect();
        if sarr.len() < 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"need at least 1 number"}
        }
        if sarr[0] != "1" && sarr[0] != "2" {
            asn1obj_new_error!{Asn1ObjBaseError,"must start 1. or 2. not [{}.]",sarr[0]}
        }

        for s in sarr.iter() {
            if s.len() == 0 {
                asn1obj_new_error!{Asn1ObjBaseError,"not allow [] empty on in the [{}]",val}
            }
        }

        oldstr = format!("{}",self.val);
        self.val = val.to_string();
        Ok(oldstr)
    }

    pub fn get_value(&self) -> String {
        return format!("{}",self.val);
    }

    fn decode_object(&self,v8 :&[u8]) -> Result<String,Box<dyn Error>> {
        let mut rets :String = "".to_string();
        let mut bn :BigUint = Zero::zero();
        let mut l :u64;
        let mut lenv :usize = v8.len();
        let mut usebn :bool;
        let mut idx :usize = 0;
        let mut bfirst :bool = true;
        let mut i :u32;

        while lenv > 0 {
            l = 0;
            usebn = false;
            loop {
                let c = v8[idx];
                idx += 1;
                lenv -= 1;
                if lenv == 0 && (c & 0x80) != 0 {
                    asn1obj_new_error!{Asn1ObjBaseError,"c [0x{:02x}] at the end",c}
                }
                if usebn {
                    bn += c & 0x7f;
                    asn1obj_log_trace!("bn [{}]",bn);
                } else {
                    l += (c & 0x7f) as u64;
                    asn1obj_log_trace!("l [{}]", l);
                }

                if (c & 0x80) == 0 {
                    break;
                }

                if !usebn && l >( ULONG_MAX >> 7) {
                    bn = Zero::zero();
                    bn += l;
                    usebn = true;
                }

                if usebn {
                    bn <<= 7;
                } else {
                    l <<= 7;
                }
            }

            if bfirst {
                bfirst = false;
                if l >= 80 {
                    i = 2;
                    if usebn {
                        bn -= 80 as u64;
                    } else {
                        l -= 80;
                    }
                } else {
                    i = (l / 40) as u32;
                    l -= (i * 40) as u64;
                }

                asn1obj_log_trace!("i {}",i);
                rets.push_str(&format!("{}",i));

            } 
            if usebn {
                rets.push_str(".");
                rets.push_str(&format!("{}",bn));
            } else {
                rets.push_str(".");
                rets.push_str(&format!("{}", l));
            }
        }

        Ok(rets)
    }

    fn encode_object(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        let mut idx :usize = 0;
        let sarr :Vec<&str> = self.val.split(".").collect();
        let  mut curn :u64 = 0;
        for v in sarr.iter() {
            match u64::from_str_radix(v,10) {
                Ok(cn) => {
                    if idx < 2 {
                        if idx == 0 {
                            curn = cn;
                        } else {
                            curn *= 40;
                            curn += cn;

                            retv.push(curn as u8);
                            curn = 0;
                        }

                    } else {
                        let mut maxidx :usize = 0;

                        curn = cn;
                        loop {
                            if (curn >> (maxidx * 7))  == 0 {
                                break;
                            }
                            maxidx += 1;
                        }

                        if maxidx == 0 {
                            retv.push(0);
                        } else {
                            while maxidx > 1 {
                                let bb :u8 = ((cn >> ((maxidx - 1) * 7)) & 0x7f) as u8;
                                retv.push(bb | 0x80 );
                                maxidx -= 1;
                            }
                            if maxidx == 1 {
                                let bb :u8 = (cn & 0x7f) as u8;
                                retv.push(bb);
                            }
                        }

                    }
                    idx += 1;
                },
                Err(e) => {
                    match BigUint::from_str(v) {
                        Ok(bn2) => {
                            if idx < 2 {
                                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] at [{}] with bigint", self.val,v}
                            }

                            let mut maxidx :usize = 0;
                            loop {
                                let bn :BigUint = bn2.clone();
                                let cb :BigUint = bn.shr(maxidx * 7);
                                let zb :BigUint = Zero::zero();
                                if cb.eq(&zb) {
                                    break;
                                }
                                maxidx += 1;
                            }

                            if maxidx < 1 {
                                asn1obj_new_error!{Asn1ObjBaseError ,"bignum is {} to small", bn2}
                            } else {
                                while maxidx > 1 {
                                    let bn :BigUint = bn2.clone();
                                    let cb :BigUint = bn.shr((maxidx - 1) * 7);
                                    let bv :Vec<u8> = cb.to_bytes_le();
                                    let bb :u8 = bv[0] & 0x7f;
                                    retv.push(bb | 0x80);
                                    maxidx -= 1;
                                }

                                let bv :Vec<u8> = bn2.to_bytes_le();
                                let bb :u8 = bv[0] & 0x7f;
                                retv.push(bb);
                            }

                            idx += 1;
                        },
                        Err(_e2) => {
                            asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] at [{}] {:?}", self.val,v,e}
                        }
                    }
                }
            }
        }
        Ok(retv)
    }
}


impl Asn1Op for Asn1Object {
    fn init_asn1() -> Self {
        Asn1Object {
            val : ASN1_OBJECT_DEFAULT_STR.to_string(),
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_OBJECT_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_OBJECT_FLAG [0x{:02x}]", flag,ASN1_OBJECT_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        let s = self.decode_object(&code[hdrlen..(hdrlen+totallen)])?;
        self.val = s;
        asn1obj_log_trace!("Asn1Object [{}]",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8>;
        if self.val.len() == 0 {
            asn1obj_new_error!{Asn1ObjBaseError,"not set val yet"}
        }
        let vv :Vec<u8> = self.encode_object()?;
        retv = asn1obj_format_header(ASN1_OBJECT_FLAG as u64,vv.len() as u64);
        for v in vv.iter() {
            retv.push(*v);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_OBJECT {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct Asn1Enumerated {
    pub val :i64,
    data :Vec<u8>,
}

impl Asn1Enumerated {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = 0;
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if !vmap.is_i64() && !vmap.is_string() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or i64",key}
        }
        if vmap.is_i64() {
            let c = vmap.as_i64().unwrap();
            self.val = c ;
        } else if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            match c.parse::<i64>() {
                Ok(fi) => {
                    self.val = fi;
                },
                Err(e) => {
                    asn1obj_new_error!{Asn1ObjBaseError,"{} val {} error {:?}", key,c,e}
                }
            }
        }
        return Ok(1);
    }
}

impl Asn1Op for Asn1Enumerated {
    fn init_asn1() -> Self {
        Asn1Enumerated {
            val : 0,
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        let mut ival :i64;
        let mut neg :bool = false;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_ENUMERATED_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_ENUMERATED_FLAG [0x{:02x}]", flag,ASN1_ENUMERATED_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen < 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"need 1 length"}
        }
        if (code[hdrlen] & 0x80) != 0 {
            neg = true;
        }



        if neg {
            let mut uval :u64;
            uval = 0;
            for i in 0..totallen {
                uval <<= 8;
                uval += (code[hdrlen+i]) as u64;
                asn1obj_log_trace!("[0x{:x}]", uval);
            }

            if uval <= ASN1_MAX_INT_1 {
                ival = (ASN1_MAX_INT_1 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_2 {
                ival = (ASN1_MAX_INT_2 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_3 {
                ival = (ASN1_MAX_INT_3 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_4 {
                ival = (ASN1_MAX_INT_4 - uval + 1) as i64;
            } else if uval <= ASN1_MAX_INT_5 {
                ival = (ASN1_MAX_INT_5 - uval + 1) as i64;
            } else {
                asn1obj_new_error!{Asn1ObjBaseError,"invalid uval [0x{:x}]", uval}
            }

            asn1obj_log_trace!("ival {}",ival);
            ival = -ival;
        } else {                
            ival = 0;
            for i in 0..totallen {
                ival <<= 8;
                ival += (code[hdrlen+i]) as i64;
            }
        }
        self.val = ival;
        asn1obj_log_trace!("Asn1Enumerated {}",self.val);
        self.data = Vec::new();
        for i in 0..(hdrlen + totallen) {
            self.data.push(code[i]);
        }
        retv= hdrlen + totallen;
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> = Vec::new();
        retv.push(ASN1_ENUMERATED_FLAG);
        retv.push(8);
        if self.val >= 0 {
            if self.val < ASN1_MAX_INT_NEG_1 as i64 {
                retv.push((self.val & 0xff) as u8);
                retv[1] = 1;
            } else if self.val < ASN1_MAX_INT_NEG_2 as i64 {
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 2;
            } else if self.val < ASN1_MAX_INT_NEG_3 as i64 {
                retv.push(((self.val >> 16) & 0xff) as u8);
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 3;
            } else if self.val < ASN1_MAX_INT_NEG_4 as i64 {
                retv.push(((self.val >> 24) & 0xff) as u8);
                retv.push(((self.val >> 16) & 0xff) as u8);
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 4;
            } else if self.val < ASN1_MAX_INT_NEG_5 as i64 {
                retv.push(((self.val >> 32) & 0xff) as u8);
                retv.push(((self.val >> 24) & 0xff) as u8);
                retv.push(((self.val >> 16) & 0xff) as u8);
                retv.push(((self.val >> 8) & 0xff) as u8);
                retv.push((self.val & 0xff) as u8);
                retv[1] = 5;
            } else {
                asn1obj_new_error!{Asn1ObjBaseError,"value [0x{:x}] > [0x{:x}]", self.val, ASN1_MAX_INT_NEG_4}
            }
        } else {
            let ival :i64 = - self.val;
            let mut uval :u64 = self.val as u64;
            uval = uval ^ 0;
            asn1obj_log_trace!("ival [{}] uval [{}]",ival,uval);
            if ival <= ASN1_MAX_INT_NEG_1 as i64 {
                retv.push((uval & 0xff) as u8);
                retv[1] = 1;
            } else if ival <= ASN1_MAX_INT_NEG_2 as i64 {
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 2;
            } else if ival <= ASN1_MAX_INT_NEG_3 as i64 {
                retv.push(((uval >> 16) & 0xff) as u8);
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 3;
            } else if ival <= ASN1_MAX_INT_NEG_4 as i64 {
                retv.push(((uval >> 24) & 0xff) as u8);
                retv.push(((uval >> 16) & 0xff) as u8);
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 4;
            } else if ival <= ASN1_MAX_INT_NEG_5 as i64 {
                retv.push(((uval >> 32) & 0xff ) as u8);
                retv.push(((uval >> 24) & 0xff) as u8);
                retv.push(((uval >> 16) & 0xff) as u8);
                retv.push(((uval >> 8) & 0xff) as u8);
                retv.push((uval & 0xff) as u8);
                retv[1] = 5;
            } else {
                asn1obj_new_error!{Asn1ObjBaseError,"neg value [0x{:x}] >= [0x{:x}]", uval, ASN1_MAX_INT_NEG_4}
            }
            asn1obj_log_trace!("retv {:?}", retv);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_ENUMERATED {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct Asn1String {
    pub val :String,
    data :Vec<u8>,
}


impl Asn1String {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let setjson = serde_json::from_str(&format!("{}",self.val)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = "".to_string();
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if  !vmap.is_string() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string",key}
        }

        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            self.val = format!("{}",c);
        }
        return Ok(1);
    }
}

impl Asn1Op for Asn1String {
    fn init_asn1() -> Self {
        Asn1String {
            val : "".to_string(),
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_UTF8STRING_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_UTF8STRING_FLAG [0x{:02x}]", flag,ASN1_UTF8STRING_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }


        let mut retm = BytesMut::with_capacity(totallen);
        for i in 0..totallen {
            retm.put_u8(code[hdrlen + i]);
        }
        let a = retm.freeze();
        self.val = String::from_utf8_lossy(&a).to_string();
        asn1obj_log_trace!("Asn1String [{}]",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let vcode = self.val.as_bytes();
        let llen :u64 = (vcode.len() ) as u64;
        let mut retv :Vec<u8>;

        retv = asn1obj_format_header(ASN1_UTF8STRING_FLAG as u64,llen);

        for i in 0..vcode.len() {
            retv.push(vcode[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_STRING {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Asn1PrintableString {
    pub val :String,
    pub flag :u8,
    data :Vec<u8>,
}

impl Asn1PrintableString {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut setjson :serde_json::value::Value = serde_json::from_str("{}").unwrap();
        let cs = serde_json::from_str(&format!("{}",self.val)).unwrap();
        let ci = serde_json::from_str(&format!("{}",self.flag)).unwrap();
        setjson[ASN1_JSON_PRINTABLE_STRING] = cs;
        setjson[ASN1_JSON_INNER_FLAG] = ci;
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = "".to_string();
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if  !vmap.is_string() && !vmap.is_object() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or object",key}
        }

        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            self.val = format!("{}",c);
            self.flag = ASN1_PRINTABLE_FLAG;
        } else if vmap.is_object() {
            let c = vmap.as_object().unwrap();
            let k = c.get(ASN1_JSON_PRINTABLE_STRING);
            if k.is_none() {
                asn1obj_new_error!{Asn1ObjBaseError,"{} not found {} in Asn1PrintableString object",key,ASN1_JSON_PRINTABLE_STRING}
            } 
            let k = k.unwrap();
            if !k.is_string() {
                asn1obj_new_error!{Asn1ObjBaseError,"{}:{} not string",key,ASN1_JSON_PRINTABLE_STRING}
            }
            self.val = format!("{}",k.as_str().unwrap());
            self.flag = ASN1_PRINTABLE_FLAG;
            let k = c.get(ASN1_JSON_INNER_FLAG);
            if k.is_some()  {
                let k = k.unwrap();
                if k.is_i64() {
                    let ival = k.as_i64().unwrap() as u8;
                    if ival != ASN1_PRINTABLE_FLAG && ival != ASN1_PRINTABLE2_FLAG  && ival != ASN1_UTF8STRING_FLAG {
                        asn1obj_new_error!{Asn1ObjBaseError,"{}:{} not valid flag",key,ASN1_JSON_INNER_FLAG}
                    }
                    self.flag = ival;                    
                }
            }
        }
        return Ok(1);
    }
}

impl Asn1Op for Asn1PrintableString {
    fn init_asn1() -> Self {
        Asn1PrintableString {
            val : "".to_string(),
            flag : ASN1_PRINTABLE_FLAG,
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_PRINTABLE_FLAG as u64 && flag != ASN1_PRINTABLE2_FLAG as u64  && flag != ASN1_UTF8STRING_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != (ASN1_PRINTABLE_FLAG [0x{:02x}] || ASN1_PRINTABLE2_FLAG [0x{:02x}] || ASN1_UTF8STRING_FLAG [0x{:02x}] )", flag,ASN1_PRINTABLE_FLAG,ASN1_PRINTABLE2_FLAG,ASN1_UTF8STRING_FLAG}
        }

        self.flag = flag as u8;

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }


        let mut retm = BytesMut::with_capacity(totallen);
        for i in 0..totallen {
            retm.put_u8(code[hdrlen + i]);
        }
        let a = retm.freeze();
        self.val = String::from_utf8_lossy(&a).to_string();
        asn1obj_log_trace!("Asn1PrintableString [{}]",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let vcode = self.val.as_bytes();
        let llen :u64 = (vcode.len() ) as u64;
        let mut retv :Vec<u8>;

        retv = asn1obj_format_header(self.flag as u64,llen);

        for i in 0..vcode.len() {
            retv.push(vcode[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_PRINTABLE_STRING {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct Asn1IA5String {
    pub val :String,
    pub flag :u8,
    data :Vec<u8>,
}

impl Asn1IA5String {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut setjson :serde_json::value::Value = serde_json::from_str("{}").unwrap();
        let cs = serde_json::from_str(&format!("{}",self.val)).unwrap();
        let ci = serde_json::from_str(&format!("{}",self.flag)).unwrap();
        setjson[ASN1_JSON_IA5STRING] = cs;
        setjson[ASN1_JSON_INNER_FLAG] = ci;
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = "".to_string();
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if  !vmap.is_string() && !vmap.is_object() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or object",key}
        }

        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            self.val = format!("{}",c);
            self.flag = ASN1_PRINTABLE_FLAG;
        } else if vmap.is_object() {
            let c = vmap.as_object().unwrap();
            let k = c.get(ASN1_JSON_IA5STRING);
            if k.is_none() {
                asn1obj_new_error!{Asn1ObjBaseError,"{} not found {} in Asn1PrintableString object",key,ASN1_JSON_IA5STRING}
            } 
            let k = k.unwrap();
            if !k.is_string() {
                asn1obj_new_error!{Asn1ObjBaseError,"{}:{} not string",key,ASN1_JSON_IA5STRING}
            }
            self.val = format!("{}",k.as_str().unwrap());
            self.flag = ASN1_PRINTABLE2_FLAG;
            let k = c.get(ASN1_JSON_INNER_FLAG);
            if k.is_some()  {
                let k = k.unwrap();
                if k.is_i64() {
                    let ival = k.as_i64().unwrap() as u8;
                    if ival != ASN1_PRINTABLE2_FLAG  {
                        asn1obj_new_error!{Asn1ObjBaseError,"{}:{} not valid flag",key,ASN1_JSON_INNER_FLAG}
                    }
                    self.flag = ival;                    
                }
            }
        }
        return Ok(1);
    }
}

impl Asn1Op for Asn1IA5String {
    fn init_asn1() -> Self {
        Asn1IA5String {
            val : "".to_string(),
            flag : ASN1_PRINTABLE2_FLAG,
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_PRINTABLE2_FLAG as u64   {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != (ASN1_PRINTABLE2_FLAG [0x{:02x}])", flag,ASN1_PRINTABLE2_FLAG}
        }

        self.flag = flag as u8;

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }


        let mut retm = BytesMut::with_capacity(totallen);
        for i in 0..totallen {
            retm.put_u8(code[hdrlen + i]);
        }
        let a = retm.freeze();
        self.val = String::from_utf8_lossy(&a).to_string();
        asn1obj_log_trace!("Asn1IA5String [{}]",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let vcode = self.val.as_bytes();
        let llen :u64 = (vcode.len() ) as u64;
        let mut retv :Vec<u8>;

        retv = asn1obj_format_header(self.flag as u64,llen);

        for i in 0..vcode.len() {
            retv.push(vcode[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s = asn1_format_line(tab,&(format!("{}: ASN1_IA5STRING {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Asn1Time {
    val :String,
    origval : String,
    data :Vec<u8>,
    utag :u8,
}

impl Asn1Time {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut setjson :serde_json::value::Value = serde_json::from_str("{}").unwrap();
        if self.origval.len() > 0 {
            setjson[ASN1_JSON_TIME] = serde_json::from_str(&format!("{}",self.origval)).unwrap();
        } else {
            setjson[ASN1_JSON_TIME] = serde_json::from_str(&format!("{}",self.val)).unwrap();
        }
        setjson[ASN1_JSON_INNER_FLAG] = serde_json::from_str(&format!("{}",self.utag)).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = ASN1_TIME_DEFAULT_STR.to_string();
            self.origval = "".to_string();
            self.data = Vec::new();
            self.utag = ASN1_UTCTIME_FLAG;
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if  !vmap.is_string() && !vmap.is_object() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string or object",key}
        }
        self.utag = ASN1_UTCTIME_FLAG;
        self.origval = "".to_string();

        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            let _ = self.set_value_str(c)?;
        } else if vmap.is_object() {
            let c = vmap.as_object().unwrap();
            let k = c.get(ASN1_JSON_TIME);
            if k.is_none() {
                asn1obj_new_error!{Asn1ObjBaseError,"{} not found {} in Asn1PrintableString object",key,ASN1_JSON_TIME}
            } 
            let k = k.unwrap();
            if !k.is_string() {
                asn1obj_new_error!{Asn1ObjBaseError,"{}:{} not string",key,ASN1_JSON_TIME}
            }
            let _ = self.set_value_str(k.as_str().unwrap());
            let k = c.get(ASN1_JSON_INNER_FLAG);
            if k.is_some()  {
                let k = k.unwrap();
                if k.is_i64() {
                    let ival = k.as_i64().unwrap() as u8;
                    if ival != ASN1_UTCTIME_FLAG  && ival != ASN1_GENERALTIME_FLAG {
                        asn1obj_new_error!{Asn1ObjBaseError,"{}:{} not valid flag",key,ASN1_JSON_INNER_FLAG}
                    }
                    self.utag = ival;                    
                }
            }
        }
        return Ok(1);
    }
}

impl Asn1Time {

    fn parse_value(&self, s :&str) -> Result<i64,Box<dyn Error>> {
        match i64::from_str_radix(s,10) {
            Ok(v) => {              
                return Ok(v);
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"parse [{}] error[{:?}]",s,e}
            }
        }
    }

    fn format_time_str(&self, year :i64, mon :i64,mday :i64,hour :i64, min :i64,sec :i64) -> String {
        return format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year,mon,mday,hour,min,sec);
    }

    fn get_time_val(&self, times :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let mut year :i64;
        let mut mon :i64;
        let mut mday :i64;
        let mut hour :i64;
        let mut min :i64;
        let mut sec :i64;
        asn1obj_log_trace!("times [{}]", times);

        if times.len() == 10 {
            year = self.parse_value(&times[0..4])?;
            mon = self.parse_value(&times[4..6])?;
            mday = self.parse_value(&times[6..8])?;
            hour = self.parse_value(&times[8..10])?;
            min = 0;
            sec = 0;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_ok() {
                return Ok((year,mon,mday,hour,min,sec));
            }

            /**/
            year = self.parse_value(&times[0..2])?;
            if year < 70 {
                year += 2000; 
            } else {
                year += 1900;
            }
            mon = self.parse_value(&times[2..4])?;
            mday = self.parse_value(&times[4..6])?;
            hour = self.parse_value(&times[6..8])?;
            min = self.parse_value(&times[8..10])?;
            sec = 0;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_err() {
                let e = ov.err().unwrap();
                return Err(e);
            }
            return Ok((year,mon,mday,hour,min,sec));
        } 

        if times.len() == 12 {
            year = self.parse_value(&times[0..4])?;
            mon = self.parse_value(&times[4..6])?;
            mday = self.parse_value(&times[6..8])?;
            hour = self.parse_value(&times[8..10])?;
            min = self.parse_value(&times[10..12])?;
            sec = 0;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_ok() {
                return Ok((year,mon,mday,hour,min,sec));
            }

            /**/
            year = self.parse_value(&times[0..2])?;
            if year < 70 {
                year += 2000; 
            } else {
                year += 1900;
            }
            mon = self.parse_value(&times[2..4])?;
            mday = self.parse_value(&times[4..6])?;
            hour = self.parse_value(&times[6..8])?;
            min = self.parse_value(&times[8..10])?;
            sec = self.parse_value(&times[10..12])?;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_err() {
                let e = ov.err().unwrap();
                return Err(e);
            }
            return Ok((year,mon,mday,hour,min,sec));
        }

        if times.len() >= 14 {
            year = self.parse_value(&times[0..4])?;
            mon = self.parse_value(&times[4..6])?;
            mday = self.parse_value(&times[6..8])?;
            hour = self.parse_value(&times[8..10])?;
            min = self.parse_value(&times[10..12])?;
            sec = self.parse_value(&times[12..14])?;
            let ov = self.check_data_valid(year,mon,mday,hour,min,sec);
            if ov.is_err() {
                let e = ov.err().unwrap();
                return Err(e);
            }
            return Ok((year,mon,mday,hour,min,sec));
        }

        asn1obj_new_error!{Asn1ObjBaseError,"not valid [{}] times", times}

    }

    #[allow(deprecated)]
    fn extract_encode_value(&self, s :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let mut year :i64;
        let mut mon :i64;
        let mut mday :i64;
        let mut hour :i64;
        let mut min :i64;
        let mut sec :i64;
        let mut dt :DateTime<Utc>;

        let c :String = "^(([0-9]+)(\\.[0-9]+)?(([-\\+])([0-9]+))?([Z|X]?))$".to_string();
        let ro = Regex::new(&c);
        if ro.is_err() {
            let e = ro.err().unwrap();
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] error[{:?}]", c,e}
        }
        let reex = ro.unwrap();
        let co = reex.captures(s);
        if co.is_none() {
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] capture [{}] none", c,s}
        }

        asn1obj_log_trace!("encoded value [{}]",s);

        let v = co.unwrap();
        let times :String;
        let zs :String;
        let diffs :String;

        times = format!("{}",v.get(2).map_or("", |m| m.as_str()));
        if times.len() < 10 {
            asn1obj_new_error!{Asn1ObjBaseError,"[{}] first part less < 10", s}
        }

        zs = format!("{}",v.get(7).map_or("", |m| m.as_str()));
        diffs = format!("{}",v.get(4).map_or("", |m| m.as_str()));

        (year,mon,mday,hour,min,sec) = self.get_time_val(&times)?;

        if diffs.len() > 0  {
            let plusorminus :String = format!("{}",v.get(5).map_or("", |m| m.as_str()));
            let offstr :String = format!("{}",v.get(6).map_or("", |m| m.as_str()));
            if zs.len() > 0 {
                if zs == "Z" {
                    asn1obj_new_error!{Asn1ObjBaseError,"not valid time string [{}]",s} 
                }               
            }

            if offstr.len() != 4 {
                asn1obj_new_error!{Asn1ObjBaseError, "offstr [{}] != 4", offstr}
            }

            let voff = self.parse_value(&offstr[0..2])?;
            if voff > 12 {
                asn1obj_new_error!{Asn1ObjBaseError,"not valid offset [{}]",offstr}
            }

            dt = Utc.ymd(year as i32,mon as u32,mday as u32).and_hms(hour as u32,min as u32,sec as u32);
            if plusorminus == "+" {
                dt = dt - Duration::hours(voff);
            } else {
                dt = dt + Duration::hours(voff);
            }
            year = dt.year() as i64;
            mon = dt.month() as i64;
            mday = dt.day() as i64;
            hour = dt.hour() as i64;
            min = dt.minute() as i64;
            sec= dt.second() as i64;
        }

        if zs.len() != 0 {
            if zs != "Z" && zs != "X" {
                asn1obj_new_error!{Asn1ObjBaseError,"not valid time [{}]",s}
            }
        }

        Ok((year,mon,mday,hour,min,sec))


    }

    fn extract_date_value(&self,s :&str) -> Result<(i64,i64,i64,i64,i64,i64),Box<dyn Error>> {
        let c :String = "([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2})(:([0-9]{2}))?".to_string();
        let ro = Regex::new(&c);
        if ro.is_err() {
            let e = ro.err().unwrap();
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] error[{:?}]", c,e}
        }
        let reex = ro.unwrap();
        let co = reex.captures(s);
        if co.is_none() {
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] capture [{}] default [{}] none", c,s, ASN1_TIME_DEFAULT_STR}
        }
        let v = co.unwrap();
        if v.len() < 8 {
            asn1obj_new_error!{Asn1ObjBaseError,"regex [{}] capture [{}] default [{}] {:?} < 8", c,s, ASN1_TIME_DEFAULT_STR,v}
        }

        let year :i64;
        let mon :i64;
        let mday :i64;
        let hour :i64;
        let min :i64;
        let sec :i64;
        let mut cc :String;

        cc = format!("{}",v.get(1).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                year = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(2).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                mon = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(3).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                mday = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(4).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                hour = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}",v.get(5).map_or("", |m| m.as_str()));
        match i64::from_str_radix(&cc,10) {
            Ok(v) => {
                min = v;
            },
            Err(e) => {
                asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
            }
        }

        cc = format!("{}", v.get(7).map_or("", |m| m.as_str()));
        if cc.len() > 0 {
            match i64::from_str_radix(&cc,10) {
                Ok(v) => {
                    sec = v;
                },
                Err(e) => {
                    asn1obj_new_error!{Asn1ObjBaseError,"can not parse [{}] in [{}] error[{:?}]", s, cc,e}
                }
            }
        } else {
            sec = 0;
        }

        Ok((year,mon,mday,hour,min,sec))
    }

    fn check_data_valid(&self, year :i64, mon :i64,mday :i64,hour :i64, min :i64,sec :i64) -> Result<(),Box<dyn Error>> {
        if year < 1900  ||  year > 2100 {
            asn1obj_new_error!{Asn1ObjBaseError,"year [{}] < 1900" ,year}
        }
        if mon < 1 || mon > 12 {
            asn1obj_new_error!{Asn1ObjBaseError,"mon {} not valid ", mon}
        }

        if mday < 1 || mday > 31 {
            asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid", mday}
        }

        if hour < 0 || hour > 23 {
            asn1obj_new_error!{Asn1ObjBaseError,"hour {} not valid", hour}  
        }

        if min < 0 || min > 59 {
            asn1obj_new_error!{Asn1ObjBaseError,"min {} not valid", min}
        }

        if sec < 0 || sec > 59 {
            asn1obj_new_error!{Asn1ObjBaseError,"sec {} not valid", sec}    
        }

        if (mon == 4 || mon == 6 || mon == 9 || mon == 11) && mday > 30 {
            asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
        }

        if mon == 2 {
            if (year % 4) != 0 && mday > 28 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 100) != 0 && mday > 29 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 100) == 0 && (year % 400) != 0 && mday > 28 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}    
            } else if (year % 4) == 0 && (year % 400) == 0 && mday > 29  {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}
            } else if mday > 28 {
                asn1obj_new_error!{Asn1ObjBaseError,"mday {} not valid in mon {}", mday,mon}
            }           
        }
        Ok(())
    }

    pub fn set_value_str(&mut self, s :&str) -> Result<(),Box<dyn Error>> {
        let (year,mon,mday,hour,min,sec) = self.extract_date_value(s)?;
        let _ = self.check_data_valid(year,mon,mday,hour,min,sec)?;
        self.val = self.format_time_str(year,mon,mday,hour,min,sec);
        self.origval = "".to_string();
        Ok(())
    }

    pub fn get_value_str(&self) -> String {
        return format!("{}",self.val);
    }

    pub fn set_value_time(&mut self,dt :&DateTime<Utc>) -> Result<(),Box<dyn Error>> {
        let (year,mon,mday,hour,min,sec) = (dt.year(),dt.month(),dt.day(),dt.hour(),dt.minute(), dt.second());
        let _ = self.check_data_valid(year as i64,mon as i64,mday as i64,hour as i64,min as i64,sec as i64)?;
        self.val = self.format_time_str(year as i64,mon as i64,mday as i64,hour as i64,min as i64,sec as i64);
        self.origval = "".to_string();
        Ok(())
    }

    #[allow(deprecated)]
    pub fn get_value_time(&self) -> Result<DateTime<Utc>,Box<dyn Error>> {
        let (year,mon,mday,hour,min,sec) = self.extract_date_value(&self.val)?;
        let dt :DateTime<Utc> = Utc.ymd(year as i32,mon as u32,mday as u32).and_hms(hour as u32,min as u32,sec as u32);
        Ok(dt)
    }
}


impl Asn1Op for Asn1Time {
    fn init_asn1() -> Self {
        Asn1Time {
            val : ASN1_TIME_DEFAULT_STR.to_string(),
            origval : "".to_string(),
            data : Vec::new(),
            utag : ASN1_UTCTIME_FLAG,
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        let (year,mon,mday,hour,min,sec):(i64,i64,i64,i64,i64,i64);
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if (flag as u8)  != ASN1_GENERALTIME_FLAG && (flag as u8) != ASN1_UTCTIME_FLAG {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}]  != ASN1_UTCTIME_FLAG [0x{:02x}] or ASN1_GENERALTIME_FLAG [0x{:02x}]", flag,ASN1_UTCTIME_FLAG,ASN1_GENERALTIME_FLAG}
        }

        self.utag = flag as u8;

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        let mut retm = BytesMut::with_capacity(totallen);
        for i in 0..totallen {
            retm.put_u8(code[hdrlen + i]);
        }
        let a = retm.freeze();

        let s = String::from_utf8_lossy(&a).to_string();
        if s.len() < 12 {
            asn1obj_new_error!{Asn1ObjBaseError,"not valid string [{}]",s}
        }

        (year,mon,mday,hour,min,sec) = self.extract_encode_value(&s)?;
        let _ = self.check_data_valid(year,mon,mday,hour,min,sec)?;
        self.origval = format!("{}",s);
        self.val = self.format_time_str(year,mon,mday,hour,min,sec);
        asn1obj_log_trace!("Asn1Time {}",self.val);
        self.data = Vec::new();
        retv = hdrlen + totallen;
        for i in 0..retv {
            self.data.push(code[i]);
        }
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let llen :u64;
        let mut retv :Vec<u8>;
        let vcode :Vec<u8>;


        let (year,mon,mday,hour,min,sec) = self.extract_date_value(&self.val)?;
        let s;
        if self.origval.len() == 0 {
            s = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z",year,mon,mday,hour,min,sec);
        } else {
            s = format!("{}",self.origval);
        }        
        vcode = s.as_bytes().to_vec();
        llen = vcode.len() as u64;

        retv = asn1obj_format_header(self.utag as u64,llen);

        for i in 0..vcode.len() {
            retv.push(vcode[i]);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {     
        let s :String;
        s = asn1_format_line(tab,&(format!("{}: ASN1_TIME {}", name, self.val)));
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}


#[derive(Clone)]
pub struct Asn1BigNum {
    pub val :BigUint,
    data :Vec<u8>,
}

impl Asn1BigNum {
    pub fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let s = format!("{}",self.val.to_str_radix(16));
        let setjson :serde_json::value::Value = serde_json::from_str(&s).unwrap();
        val[key] = setjson;
        Ok(1)
    }

    pub fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let ores = val.get(key);
        if ores.is_none() {
            self.val = BigUint::parse_bytes(b"0",16).unwrap();
            self.data = Vec::new();
            return Ok(0);
        }
        let vmap = ores.unwrap();
        if  !vmap.is_string() {
            asn1obj_new_error!{Asn1ObjBaseError,"{} not valid string",key}
        }

        if vmap.is_string() {
            let c = vmap.as_str().unwrap();
            let ores = BigUint::parse_bytes(c.as_bytes(),16);
            if ores.is_none() {
                asn1obj_new_error!{Asn1ObjBaseError,"{} {} not valid biguint",key,c}
            }
            self.val = ores.unwrap();
        }
        return Ok(1);
    }
}


impl Asn1Op for Asn1BigNum {
    fn init_asn1() -> Self {
        Asn1BigNum {
            val : Zero::zero(),
            data : Vec::new(),
        }
    }

    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let retv :usize;
        if code.len() < 2 {
            asn1obj_new_error!{Asn1ObjBaseError,"len [{}] < 2", code.len()}
        }
        let (flag,hdrlen,totallen) = asn1obj_extract_header(code)?;

        if flag != ASN1_INTEGER_FLAG as u64 {
            asn1obj_new_error!{Asn1ObjBaseError,"flag [0x{:02x}] != ASN1_INTEGER_FLAG [0x{:02x}]", flag,ASN1_INTEGER_FLAG}
        }

        if code.len() < (hdrlen + totallen) {
            asn1obj_new_error!{Asn1ObjBaseError,"code len[0x{:x}] < (hdrlen [0x{:x}] + totallen [0x{:x}])", code.len(),hdrlen,totallen}
        }

        if totallen < 1 {
            asn1obj_new_error!{Asn1ObjBaseError,"need 1 length"}
        }

        self.val = BigUint::from_bytes_be(&code[hdrlen..(hdrlen+totallen)]);
        let cc = self.val.to_bytes_be();
        asn1obj_debug_buffer_trace!(cc.as_ptr(), cc.len(),"Asn1BigNum");
        asn1obj_log_trace!("Asn1BigNum {:?}", self.val);
        self.data = Vec::new();
        for i in 0..(hdrlen + totallen) {
            self.data.push(code[i]);
        }
        retv= hdrlen + totallen;
        Ok(retv)
    }

    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut retv :Vec<u8> ;
        let v8 :Vec<u8>;
        let mut clen :usize ;
        v8 = self.val.to_bytes_be();
        clen = v8.len();
        if v8.len() > 0 && (v8[0] & 0x80) != 0x0 {
            clen = v8.len() + 1;
        }
        retv = asn1obj_format_header(ASN1_INTEGER_FLAG as u64, clen as u64);
        if clen != v8.len() {
            retv.push(0x0);
        }
        for v in v8.iter() {
            retv.push(*v);
        }
        Ok(retv)
    }

    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> { 
        let v8 = self.val.to_bytes_be();
        let mut s :String;
        if v8.len() < 8 {
            s = asn1_format_line(tab, &(format!("{}: ASN1_BIGNUM 0x{:08x}", name, self.val)));
        } else {
            let mut c :String = "".to_string();
            let mut i :usize=0;
            let mut lasti :usize = 0;
            s = asn1_format_line(tab, &(format!("{}: ASN1_BIGNUM", name)));
            while i < v8.len() {
                if (i %16) == 0 {
                    if i > 0 {
                        c.push_str("    ");
                        while lasti != i {
                            if v8[lasti] >= 0x20 && v8[lasti] <= 0x7e {
                                c.push( v8[lasti] as char);
                            } else {
                                c.push_str(".");
                            }
                            lasti += 1;
                        }
                        s.push_str(&asn1_format_line(tab + 1, &format!( "{}",c)));
                        c = "".to_string();
                    }
                    lasti = i;
                }
                if lasti != i {
                    c.push_str(":");
                }               
                c.push_str(&format!("{:02x}",v8[i]));
                i += 1;
            }
            if lasti != i {
                while (i%16) != 0 {
                    c.push_str("   ");
                    i += 1;
                }
                c.push_str("    ");
                while lasti < v8.len() {
                    if v8[lasti] >= 0x20 && v8[lasti] <= 0x7e {
                        c.push( v8[lasti] as char);
                    } else {
                        c.push_str(".");
                    }
                    lasti += 1;                    
                }
            }

            if c.len() > 0 {
                s.push_str(&asn1_format_line(tab + 1, &format!("{}",c)));
            }
        }
        iowriter.write(s.as_bytes())?;
        Ok(())
    }
}
