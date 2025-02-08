#[allow(unused_imports)]
use extargsparse_codegen::{extargs_load_commandline,ArgSet,extargs_map_function};
#[allow(unused_imports)]
use extargsparse_worker::{extargs_error_class,extargs_new_error};
#[allow(unused_imports)]
use extargsparse_worker::namespace::{NameSpaceEx};
#[allow(unused_imports)]
use extargsparse_worker::argset::{ArgSetImpl};
use extargsparse_worker::parser::{ExtArgsParser};
use extargsparse_worker::funccall::{ExtArgsParseFunc};

use std::cell::RefCell;
use std::sync::Arc;
use std::error::Error;
use std::boxed::Box;
#[allow(unused_imports)]
use regex::Regex;
#[allow(unused_imports)]
use std::any::Any;

use lazy_static::lazy_static;
use std::collections::HashMap;

#[allow(unused_imports)]
use super::loglib::*;
#[allow(unused_imports)]
use super::fileop::*;
#[allow(unused_imports)]
use super::strop::*;
#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use std::io::Write;


#[allow(unused_imports)]
use asn1obj_codegen::*;
#[allow(unused_imports)]
use asn1obj::base::*;
use asn1obj::asn1impl::*;
use asn1obj::complex::*;
#[allow(unused_imports)]
use asn1obj::{asn1obj_error_class,asn1obj_new_error};
use asn1obj::strop::asn1_format_line;
#[allow(unused_imports)]
use asn1obj_codegen::{asn1_choice,asn1_obj_selector,asn1_sequence,asn1_int_choice};

extargs_error_class!{EcLoadError}

// #[derive(Clone)]
// #[asn1_sequence()]
// pub struct X9_62_CURVEElem {
// 	pub a :Asn1OctData,
// 	pub b :Asn1OctData,
// 	pub seed :Asn1Opt<Asn1BitDataFlag>,
// }

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIALELem {
	pub k1 :Asn1Integer,
	pub k2 :Asn1Integer,
	pub k3 :Asn1Integer,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_PENTANOMIAL {
	pub elem :Asn1Seq<X9_62_PENTANOMIALELem>,
}


#[derive(Clone)]
pub struct X9_62_CURVEElem
{
    pub a : Asn1OctData, pub b : Asn1OctData, 
    pub seed : Asn1Opt < Asn1BitDataFlag > ,
}
asn1obj_error_class!{X9_62_CURVEElemErrorghoQFMP1XcAv5OsgBjDL}

impl Asn1Op for X9_62_CURVEElem {
    
    fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut mainv :serde_json::value::Value = serde_json::json!({});
        let mut idx :i32 = 0;
        
        println!("X9_62_CURVEElem.a.encode_json(\"a\",val)");
        idx += self.a.encode_json("a",&mut mainv)?;
        println!("X9_62_CURVEElem.b.encode_json(\"b\",val)");
        idx += self.b.encode_json("b",&mut mainv)?;
        println!("X9_62_CURVEElem.seed.encode_json(\"seed\",val)");
        idx += self.seed.encode_json("seed",&mut mainv)?;
        
        if key.len() > 0 {
            val[key] = mainv;
        } else {
            *val = mainv;
        }
        
        return Ok(idx);
    }
    
    fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mainv :serde_json::value::Value;
        let mut idx :i32=0;
        
        if key.len() > 0 {
            let k = val.get(key);
            if k.is_none() {
                self.a = Asn1OctData::init_asn1();
                self.b = Asn1OctData::init_asn1();
                self.seed = Asn1Opt::init_asn1();
                return Ok(0);
            }
            mainv = serde_json::json!(k.clone());
        } else {
            mainv = val.clone();
        }
        
        if !mainv.is_object() {
            asn1obj_new_error!{X9_62_CURVEElemErrorghoQFMP1XcAv5OsgBjDL,"not object to decode"}
        }
        
        println!("X9_62_CURVEElem.a.decode_json(\"a\",val)");
        idx += self.a.decode_json("a",&mainv)?;
        println!("X9_62_CURVEElem.b.decode_json(\"b\",val)");
        idx += self.b.decode_json("b",&mainv)?;
        println!("X9_62_CURVEElem.seed.decode_json(\"seed\",val)");
        idx += self.seed.decode_json("seed",&mainv)?;
        
        return Ok(idx);
    }
    
    fn init_asn1() -> Self {
        X9_62_CURVEElem {
            a : Asn1OctData::init_asn1(),
            b : Asn1OctData::init_asn1(),
            seed : Asn1Opt::init_asn1(),
        }
    }
    
    fn decode_asn1(&mut self, code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let mut retv :usize = 0;
        let mut _endsize :usize = code.len();
        let mut _outf = std::io::stderr();
        let mut _outs :String;
        let mut _lastv :usize = 0;
        let mut _i :usize;
        let mut _lasti :usize;
        _lastv = retv;
        
        _outs = format!("decode X9_62_CURVEElem.a will decode at {}\n",retv);
        let _ = _outf.write(_outs.as_bytes())?;
        let ro = self.a.decode_asn1(&code[retv.._endsize]);
        if ro.is_err() {
            let e = ro.err().unwrap();
            _i = 0;
            _lasti = _i;
            _outs = format!("a decode at [0x{:x}:{}]\n",_lastv,_lastv);
            while (_i + _lastv) < code.len() {
                if _i >= 16 {
                    _outs.push_str("    ");
                    while _lasti < _i {
                        if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                        _outs.push(code[(_lastv+_lasti)] as char);
                        } else {
                        _outs.push_str(".");
                        }
                        _lasti += 1;
                    }
                    _outs.push_str("\n");
                    break;
                }
                _outs.push_str(&format!(" 0x{:02x}",code[_i]));
                _i += 1;
            }
            if _i < 16 {
                while ( _i % 16) != 0 {
                    _outs.push_str("     ");
                    _i += 1;
                }
                while (_lasti + _lastv) < code.len() {
                    if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                        _outs.push(code[(_lastv+_lasti)] as char);
                    } else {
                        _outs.push_str(".");
                    }
                    _lasti += 1;
                }
                _outs.push_str("\n");
            }
            let _ = _outf.write(_outs.as_bytes())?;
            _outs = format!("decode X9_62_CURVEElem.a error {:?}",e);
            let _ = _outf.write(_outs.as_bytes())?;
            return Err(e);
        }
        _lastv = retv;
        retv += ro.unwrap();
        _outs = format!("decode X9_62_CURVEElem.a retv {} _lastv {}",retv,_lastv);
        _i = 0;
        _lasti = 0;
        while _i < (retv - _lastv) {
            if (_i % 16) == 0 {
                if _i > 0 {
                    _outs.push_str("    ");
                    while _lasti != _i {
                        if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                            _outs.push(code[(_lastv+_lasti)] as char);
                        } else {
                            _outs.push_str(".");
                        }
                        _lasti += 1;
                    }
                }
                _outs.push_str(&format!("\n0x{:08x}:",_i));
            }
            _outs.push_str(&format!(" 0x{:02x}", code[_lastv + _i]));
            _i += 1;
        }
        if _lasti != _i {
            while (_i % 16) != 0 {
                _outs.push_str("     ");
                _i += 1;
            }
            _outs.push_str("    ");
            while _lasti < (retv - _lastv) {
                if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                    _outs.push(code[(_lastv+_lasti)] as char);
                } else {
                    _outs.push_str(".");
                }
                _lasti += 1;
            }
        }
        _outs.push_str("\n");
        let _ = _outf.write(_outs.as_bytes())?;
        
        _outs = format!("decode X9_62_CURVEElem.b will decode at {}\n",retv);
        let _ = _outf.write(_outs.as_bytes())?;
        let ro = self.b.decode_asn1(&code[retv.._endsize]);
        if ro.is_err() {
            let e = ro.err().unwrap();
            _i = 0;
            _lasti = _i;
            _outs = format!("b decode at [0x{:x}:{}]\n",_lastv,_lastv);
            while (_i + _lastv) < code.len() {
                if _i >= 16 {
                    _outs.push_str("    ");
                    while _lasti < _i {
                        if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                        _outs.push(code[(_lastv+_lasti)] as char);
                        } else {
                        _outs.push_str(".");
                        }
                        _lasti += 1;
                    }
                    _outs.push_str("\n");
                    break;
                }
                _outs.push_str(&format!(" 0x{:02x}",code[_i]));
                _i += 1;
            }
            if _i < 16 {
                while ( _i % 16) != 0 {
                    _outs.push_str("     ");
                    _i += 1;
                }
                while (_lasti + _lastv) < code.len() {
                    if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                        _outs.push(code[(_lastv+_lasti)] as char);
                    } else {
                        _outs.push_str(".");
                    }
                    _lasti += 1;
                }
                _outs.push_str("\n");
            }
            let _ = _outf.write(_outs.as_bytes())?;
            _outs = format!("decode X9_62_CURVEElem.b error {:?}",e);
            let _ = _outf.write(_outs.as_bytes())?;
            return Err(e);
        }
        _lastv = retv;
        retv += ro.unwrap();
        _outs = format!("decode X9_62_CURVEElem.b retv {} _lastv {}",retv,_lastv);
        _i = 0;
        _lasti = 0;
        while _i < (retv - _lastv) {
            if (_i % 16) == 0 {
                if _i > 0 {
                    _outs.push_str("    ");
                    while _lasti != _i {
                        if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                            _outs.push(code[(_lastv+_lasti)] as char);
                        } else {
                            _outs.push_str(".");
                        }
                        _lasti += 1;
                    }
                }
                _outs.push_str(&format!("\n0x{:08x}:",_i));
            }
            _outs.push_str(&format!(" 0x{:02x}", code[_lastv + _i]));
            _i += 1;
        }
        if _lasti != _i {
            while (_i % 16) != 0 {
                _outs.push_str("     ");
                _i += 1;
            }
            _outs.push_str("    ");
            while _lasti < (retv - _lastv) {
                if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                    _outs.push(code[(_lastv+_lasti)] as char);
                } else {
                    _outs.push_str(".");
                }
                _lasti += 1;
            }
        }
        _outs.push_str("\n");
        let _ = _outf.write(_outs.as_bytes())?;
        
        _outs = format!("decode X9_62_CURVEElem.seed will decode at {}\n",retv);
        let _ = _outf.write(_outs.as_bytes())?;
        let ro = self.seed.decode_asn1(&code[retv.._endsize]);
        if ro.is_err() {
            let e = ro.err().unwrap();
            _i = 0;
            _lasti = _i;
            _outs = format!("seed decode at [0x{:x}:{}]\n",_lastv,_lastv);
            while (_i + _lastv) < code.len() {
                if _i >= 16 {
                    _outs.push_str("    ");
                    while _lasti < _i {
                        if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                        _outs.push(code[(_lastv+_lasti)] as char);
                        } else {
                        _outs.push_str(".");
                        }
                        _lasti += 1;
                    }
                    _outs.push_str("\n");
                    break;
                }
                _outs.push_str(&format!(" 0x{:02x}",code[_i]));
                _i += 1;
            }
            if _i < 16 {
                while ( _i % 16) != 0 {
                    _outs.push_str("     ");
                    _i += 1;
                }
                while (_lasti + _lastv) < code.len() {
                    if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                        _outs.push(code[(_lastv+_lasti)] as char);
                    } else {
                        _outs.push_str(".");
                    }
                    _lasti += 1;
                }
                _outs.push_str("\n");
            }
            let _ = _outf.write(_outs.as_bytes())?;
            _outs = format!("decode X9_62_CURVEElem.seed error {:?}",e);
            let _ = _outf.write(_outs.as_bytes())?;
            return Err(e);
        }
        _lastv = retv;
        retv += ro.unwrap();
        _outs = format!("decode X9_62_CURVEElem.seed retv {} _lastv {}",retv,_lastv);
        _i = 0;
        _lasti = 0;
        while _i < (retv - _lastv) {
            if (_i % 16) == 0 {
                if _i > 0 {
                    _outs.push_str("    ");
                    while _lasti != _i {
                        if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                            _outs.push(code[(_lastv+_lasti)] as char);
                        } else {
                            _outs.push_str(".");
                        }
                        _lasti += 1;
                    }
                }
                _outs.push_str(&format!("\n0x{:08x}:",_i));
            }
            _outs.push_str(&format!(" 0x{:02x}", code[_lastv + _i]));
            _i += 1;
        }
        if _lasti != _i {
            while (_i % 16) != 0 {
                _outs.push_str("     ");
                _i += 1;
            }
            _outs.push_str("    ");
            while _lasti < (retv - _lastv) {
                if code[_lastv + _lasti] >= 0x20 && code[_lastv + _lasti] <= 0x7e {
                    _outs.push(code[(_lastv+_lasti)] as char);
                } else {
                    _outs.push_str(".");
                }
                _lasti += 1;
            }
        }
        _outs.push_str("\n");
        let _ = _outf.write(_outs.as_bytes())?;
        _outs = format!("X9_62_CURVEElem total {}\n",retv);
        let _ = _outf.write(_outs.as_bytes())?;
        
        Ok(retv)
        
    }
    
    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let mut _v8 :Vec<u8> = Vec::new();
        let mut _outf = std::io::stderr();
        let mut _outs :String;
        let mut encv :Vec<u8>;
        
        encv = self.a.encode_asn1()?;
        for i in 0..encv.len() {
            _v8.push(encv[i]);
        }
        
        _outs = format!("format X9_62_CURVEElem.a {:?}\n",encv);
        _outf.write(_outs.as_bytes())?;
        
        encv = self.b.encode_asn1()?;
        for i in 0..encv.len() {
            _v8.push(encv[i]);
        }
        
        _outs = format!("format X9_62_CURVEElem.b {:?}\n",encv);
        _outf.write(_outs.as_bytes())?;
        
        encv = self.seed.encode_asn1()?;
        for i in 0..encv.len() {
            _v8.push(encv[i]);
        }
        
        _outs = format!("format X9_62_CURVEElem.seed {:?}\n",encv);
        _outf.write(_outs.as_bytes())?;
        
        Ok(_v8)
        
    }
    
    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let mut s :String;
        s = asn1_format_line(tab,&format!("{} X9_62_CURVEElem", name));
        iowriter.write(s.as_bytes())?;
        
        s = format!("a");
        self.a.print_asn1(&s,tab + 1, iowriter)?;
        
        s = format!("b");
        self.b.print_asn1(&s,tab + 1, iowriter)?;
        
        s = format!("seed");
        self.seed.print_asn1(&s,tab + 1, iowriter)?;
        
        Ok(())
        
    }
    
}



#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CURVE {
	pub elem :Asn1Seq<X9_62_CURVEElem>,
}

#[derive(Clone)]
#[asn1_obj_selector(other=default,onBasis="1.2.840.10045.1.2.3.1",tpBasis="1.2.840.10045.1.2.3.2",ppBasis="1.2.840.10045.1.2.3.3")]
pub struct X962Selector  {
	pub val :Asn1Object,
}

#[derive(Clone)]
#[asn1_choice(selector=otype)]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM_CHOICE {
	pub otype : X962Selector,
	pub onBasis : Asn1Null,
	pub tpBasis : Asn1BigNum,
	pub ppBasis : X9_62_PENTANOMIAL,
	pub other :Asn1Any,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CHARACTERISTIC_TWO_ELEM {
	pub m :Asn1Integer,
	pub elemchoice : X9_62_CHARACTERISTIC_TWO_ELEM_CHOICE,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_CHARACTERISTIC_TWO {
	pub elem :Asn1Seq<X9_62_CHARACTERISTIC_TWO_ELEM>,
}


#[derive(Clone)]
#[asn1_obj_selector(prime="1.2.840.10045.1.1",char_two="1.2.840.10045.1.2")]
pub struct X964FieldSelector {
	pub val :Asn1Object,
}

#[derive(Clone)]
#[asn1_choice(selector=fieldType)]
pub struct X9_62_FIELDIDElem {
	pub fieldType :X964FieldSelector,
	pub prime : Asn1BigNum,
	pub char_two :X9_62_CHARACTERISTIC_TWO,
}

#[derive(Clone)]
#[asn1_sequence()]
pub struct X9_62_FIELDID {
	pub elem :Asn1Seq<X9_62_FIELDIDElem>,
}


#[derive(Clone)]
#[asn1_sequence()]
pub struct ECPARAMETERSElem {
	pub version : Asn1Integer,
	pub fieldID : X9_62_FIELDID,
	pub curve :X9_62_CURVE,
	pub base :Asn1OctData,
	pub order :Asn1BigNum,
	pub cofactor : Asn1Opt<Asn1BigNum>,

}


#[asn1_sequence()]
#[derive(Clone)]
pub struct ECPARAMETERS {
	pub elem :Asn1Seq<ECPARAMETERSElem>,
}


//#[asn1_int_choice(selector=itype,named_curve=0,parameters=1,implicitCA=2)]
//#[derive(Clone)]
//pub struct ECPKPARAMETERS {
//	pub itype :i32,
//	pub named_curve :Asn1Object,
//	pub parameters : ECPARAMETERS,
//	pub implicitCA : Asn1Null,
//}


#[derive(Clone)] 
pub struct ECPKPARAMETERS
{
    pub itype : i32, pub named_curve : Asn1Object, pub parameters :
    ECPARAMETERS, pub implicitCA : Asn1Null,
}
asn1obj_error_class!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError}
 
impl Asn1Op for ECPKPARAMETERS {
    fn encode_json(&self, key :&str,val :&mut serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mut mainv :serde_json::value::Value = serde_json::json!({});
        let mut idx :i32 = 0;
        let mut cint :Asn1Integer = Asn1Integer::init_asn1();
         
        cint.val = self.itype as i64;
        println!("ECPKPARAMETERS.encode_json(\"itype\",val)");
        idx += cint.encode_json("itype",&mut mainv)?;
         
        if self.itype == 1 {
        println!("ECPKPARAMETERS.parameters.encode_json(\"parameters\",val)");
            idx += self.parameters.encode_json("parameters",&mut mainv)?;
        } else if self.itype == 2 {
        println!("ECPKPARAMETERS.implicitCA.encode_json(\"implicitCA\",val)");
            idx += self.implicitCA.encode_json("implicitCA",&mut mainv)?;
        } else if self.itype == 0 {
        println!("ECPKPARAMETERS.named_curve.encode_json(\"named_curve\",val)");
            idx += self.named_curve.encode_json("named_curve",&mut mainv)?;
        } else {
            asn1obj_new_error!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError,"not support {} value",self.itype}
        }
         
        if key.len() > 0 {
            val[key] = mainv;
        } else {
            *val = mainv;
        }
         
        return Ok(idx);
    }
    
    fn decode_json(&mut self, key :&str, val :&serde_json::value::Value) -> Result<i32,Box<dyn Error>> {
        let mainv :serde_json::value::Value;
        let mut idx :i32=0;
        let mut cint :Asn1Integer = Asn1Integer::init_asn1();
         
        if key.len() > 0 {
            let k = val.get(key);
            if k.is_none() {
                self.itype = -1;
                self.named_curve = Asn1Object::init_asn1();
                self.parameters = ECPARAMETERS::init_asn1();
                self.implicitCA = Asn1Null::init_asn1();
                return Ok(0);
            }
            mainv = serde_json::json!(k.clone());
        } else {
            mainv = val.clone();
        }
         
        if !mainv.is_object() {
            asn1obj_new_error!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError,"not object to decode"}
        }
         
        println!("ECPKPARAMETERS.decode_json(\"itype\",val)");
        idx += cint.decode_json("itype",&mainv)?;
        self.itype = cint.val as i32;
         
        if self.itype == 1 {
        println!("ECPKPARAMETERS.parameters.decode_json(\"parameters\",val)");
            idx += self.parameters.decode_json("parameters",&mainv)?;
        } else if self.itype == 2 {
        println!("ECPKPARAMETERS.implicitCA.decode_json(\"implicitCA\",val)");
            idx += self.implicitCA.decode_json("implicitCA",&mainv)?;
        } else if self.itype == 0 {
        println!("ECPKPARAMETERS.named_curve.decode_json(\"named_curve\",val)");
            idx += self.named_curve.decode_json("named_curve",&mainv)?;
        } else {
            asn1obj_new_error!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError,"not support {} value decode",self.itype}
        }
         
        return Ok(idx);
    }
    
    fn init_asn1() -> Self {
        ECPKPARAMETERS {
            itype : -1,
            named_curve : Asn1Object::init_asn1(),
            parameters : ECPARAMETERS::init_asn1(),
            implicitCA : Asn1Null::init_asn1(),
        }
    }
    
    fn decode_asn1(&mut self,code :&[u8]) -> Result<usize,Box<dyn Error>> {
        let mut ores : Result<usize,Box<dyn Error>>;
        let mut _outf = std::io::stderr();
        let mut _outs :String;
         
        _outs = format!("will decode parameters\n");
        _outf.write(_outs.as_bytes())?;
        ores = self.parameters.decode_asn1(code);
        if ores.is_ok() {
            self.itype = 1;
            return Ok(ores.unwrap());
        }
         
        _outs = format!("will decode implicitCA\n");
        _outf.write(_outs.as_bytes())?;
        ores = self.implicitCA.decode_asn1(code);
        if ores.is_ok() {
            self.itype = 2;
            return Ok(ores.unwrap());
        }
         
        _outs = format!("will decode named_curve\n");
        _outf.write(_outs.as_bytes())?;
        ores = self.named_curve.decode_asn1(code);
        if ores.is_ok() {
            self.itype = 0;
            return Ok(ores.unwrap());
        }
         
        asn1obj_new_error!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError,"not supported type"}
    }
    
    fn encode_asn1(&self) -> Result<Vec<u8>,Box<dyn Error>> {
        let retv :Vec<u8>;
         
        if self.itype == 1 {
            retv = self.parameters.encode_asn1()?;
        } else if self.itype == 2 {
            retv = self.implicitCA.encode_asn1()?;
        } else if self.itype == 0 {
            retv = self.named_curve.encode_asn1()?;
        } else {
            asn1obj_new_error!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError,"not supported type {}", self.itype}
        }
         
        Ok(retv)
    }
    
    fn print_asn1<U :Write>(&self,name :&str,tab :i32, iowriter :&mut U) -> Result<(),Box<dyn Error>> {
        let  s :String;
         
        s = asn1_format_line(tab,&format!("{}.itype type {}",name,self.itype));
        iowriter.write(s.as_bytes())?;
         
        if self.itype == 1 {
            self.parameters.print_asn1("parameters",tab+1,iowriter)?;
        } else if self.itype == 2 {
            self.implicitCA.print_asn1("implicitCA",tab+1,iowriter)?;
        } else if self.itype == 0 {
            self.named_curve.print_asn1("named_curve",tab+1,iowriter)?;
        } else {
            asn1obj_new_error!{ECPKPARAMETERSBiAxjz8XuTwG8R5EError,"not supported type {}", self.itype}
        }
         
        Ok(())
    }
}




fn ecprivjsonenc_handler(ns :NameSpaceEx,_optargset :Option<Arc<RefCell<dyn ArgSetImpl>>>,_ctx :Option<Arc<RefCell<dyn Any>>>) -> Result<(),Box<dyn Error>> {
	let sarr :Vec<String> = ns.get_array("subnargs");
	if sarr.len() < 1 {
		extargs_new_error!{EcLoadError,"need jsonfile"}
	}

	let jsons = read_file(&sarr[0])?;
	let jval :serde_json::Value = serde_json::from_str(&jsons)?;
	let mut bag :ECPKPARAMETERS = ECPKPARAMETERS::init_asn1();
	let _ = bag.decode_json("",&jval)?;
	let cstr = format!("[{}] format ECPKPARAMETERS\n",sarr[0]);
	let mut outf = std::io::stdout();
	let _ = bag.print_asn1(&cstr,0,&mut outf)?;
	let output = ns.get_string("output");
	if output.len() > 0 {
		let code = bag.encode_asn1()?;
		write_file_bytes(&output,&code)?;
	}
	Ok(())
}



#[extargs_map_function(ecprivjsonenc_handler)]
pub fn load_ec_parser(parser :ExtArgsParser) -> Result<(),Box<dyn Error>> {
	let cmdline = format!(r#"
	{{
		"ecprivjsonenc<ecprivjsonenc_handler>##jsonfile to load ecpriv##" : {{
			"$" : 1
		}}
	}}
	"#);
	extargs_load_commandline!(parser,&cmdline)?;
	Ok(())
}