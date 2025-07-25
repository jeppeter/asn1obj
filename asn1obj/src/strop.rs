use std::cell::{RefCell};

thread_local!{
	static ASN1_DEBUG_TABS :RefCell<usize> = {
		RefCell::new(0)
	};
}


pub fn asn1_enter_debug() -> usize {
	let mut retv :usize = 0;
	ASN1_DEBUG_TABS.with_borrow_mut(|x| {
		*x += 1;
		retv = *x;
	});
	retv
}

pub fn asn1_leave_debug() -> usize {
	let mut retv :usize = 0;
	ASN1_DEBUG_TABS.with_borrow_mut(|x| {
		if *x >= 1 {
			*x -= 1;	
		}		
		retv = *x;
	});
	retv
}

fn asn1_get_debug() -> usize {
	let mut retv :usize = 0;
	ASN1_DEBUG_TABS.with_borrow(|x| {
		retv = *x;
	});
	retv
}

pub fn asn1_format_debug_tabs() -> String {
	let mut rets :String = "".to_string();
	let retv = asn1_get_debug();
	let mut idx :usize = 0;
	while idx < retv {
		rets.push_str("    ");
		idx += 1;
	}
	rets
}

#[macro_export]
macro_rules! asn1_format_debug {
	($($arg:tt)+) => {
		let mut _c = format!($($arg)+);
		_c.push_str("\n");
		let mut _stderr = std::io::stderr();
		let _cs = asn1_format_debug_tabs();
		let _ = _stderr.write_all(_cs.as_bytes());
		let _ = _stderr.write_all(_c.as_bytes());
	};
}

#[macro_export]
macro_rules! asn1_format_debug_buffer {
	($buf:expr,$len:expr,$($arg:tt)+) => {
		let mut _c :String = format!("");
		let _ptr :*const u8 = $buf as *const u8;
		let  mut _ci :usize;
		let _totallen: usize = $len as usize;
		let _cs = asn1_format_debug_tabs();
		let mut _i :usize = 0;
		let mut _lasti :usize = 0;
		let mut _nb :u8;
		let mut _stderr = std::io::stderr();

		_c.push_str(&format!($($arg)+));
		_c.push_str(&format!(" buffer [{:?}][{}]",_ptr,_totallen));

		while _i < _totallen {
			if (_i % 16) == 0 {
				if _i > 0 {
					_c.push_str(&format!("    "));
					while _lasti < _i {
						unsafe{
							_nb = *_ptr.offset(_lasti as isize);	
						}
						
						if _nb >= 0x20 && _nb <= 0x7e {
							_c.push(_nb as char);
						} else {
							_c.push_str(".");
						}
						_lasti += 1;						
					}					
				}
				_c.push_str("\n");
				let _ = _stderr.write_all(_cs.as_bytes());
				let _ = _stderr.write_all(_c.as_bytes());
				_c = "".to_string();
				_c.push_str(&format!("0x{:08x}:",_i));
			}

			unsafe {_nb = *_ptr.offset(_i as isize);}			
			_c.push_str(&format!(" 0x{:02x}",_nb));
			_i += 1;
		}

		if _lasti != _i {
			while (_i % 16) != 0 {
				_c.push_str("     ");
				_i += 1;
			}
			_c.push_str("    ");
			while _lasti < _totallen {
				unsafe{
					_nb = *_ptr.offset(_lasti as isize);	
				}
						
				if _nb >= 0x20 && _nb <= 0x7e {
					_c.push(_nb as char);
				} else {
					_c.push_str(".");
				}
				_lasti += 1;
			}
			_c.push_str("\n");
			let _ = _stderr.write_all(_cs.as_bytes());
			let _ = _stderr.write_all(_c.as_bytes());
		}
	};
}


pub fn asn1_format_line(tab :i32, s :&str) -> String {
	let mut rets :String = "".to_string();
	for _i in 0..tab {
		rets.push_str("    ");
	}
	rets.push_str(s);
	rets.push_str("\n");
	rets
}
