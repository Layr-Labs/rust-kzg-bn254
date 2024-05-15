use ark_bn254::{Fq, Fr};
use ark_ff::{BigInt, Field, PrimeField};
use ark_std::{ops::Mul};

pub fn montgomery_reduce(z_0: &u64, z_1: &u64, z_2: &u64, z_3: &u64) -> (u64, u64, u64, u64) {
    
    let mut z0 = z_0.clone();
    let mut z1 = z_1.clone();
    let mut z2 = z_2.clone();
    let mut z3 = z_3.clone();
    let inv: u64 = 9786893198990664585;
    let modulus = <Fq as PrimeField>::MODULUS.0;

    let mut m: u64 = z0.wrapping_mul(inv);
	let mut C = madd0(m, modulus[0], z0);
	(C, z0) = madd2(m, modulus[1], z1, C);
	(C, z1) = madd2(m, modulus[2], z2, C);
	(C, z2) = madd2(m, modulus[3], z3, C);
	z3 = C;

    m = z0.wrapping_mul(inv);
	C = madd0(m, modulus[0], z0);
	(C, z0) = madd2(m, modulus[1], z1, C);
	(C, z1) = madd2(m, modulus[2], z2, C);
	(C, z2) = madd2(m, modulus[3], z3, C);
	z3 = C;

    m = z0.wrapping_mul(inv);
	C = madd0(m, modulus[0], z0);
	(C, z0) = madd2(m, modulus[1], z1, C);
	(C, z1) = madd2(m, modulus[2], z2, C);
	(C, z2) = madd2(m, modulus[3], z3, C);
	z3 = C;

    
    m = z0.wrapping_mul(inv);
	C = madd0(m, modulus[0], z0);
	(C, z0) = madd2(m, modulus[1], z1, C);
	(C, z1) = madd2(m, modulus[2], z2, C);
	(C, z2) = madd2(m, modulus[3], z3, C);
	z3 = C;

    let is_smaller_than_modulus = z3 < modulus[3] || (z3 == modulus[3] && (z2 < modulus[2] || (z2 == modulus[2] && (z1 < modulus[1] || (z1 == modulus[1] && (z0 < modulus[0]))))));

    if !is_smaller_than_modulus {
        let mut b;
        (z0, b) = sub_64(z0, modulus[0], 0);
		(z1, b) = sub_64(z1, modulus[1], b);
		(z2, b) = sub_64(z2, modulus[2], b);
		(z3, _) = sub_64(z3, modulus[3], b);
    }

    (z0, z1, z2, z3)

}

fn sub_64(x: u64, y: u64, borrow: u64) -> (u64, u64) {
    // Perform the subtraction with the initial borrow
    let (mut diff, borrow_out1) = x.overflowing_sub(y);
    let (diff, borrow_out2) = diff.overflowing_sub(borrow);

    // Calculate the final borrow out using bitwise operations
    // This replicates the bit logic in the original Go function
    let borrow_out = ((!x & y) | (!(x ^ y) & diff)) >> 63;

    (diff, borrow_out)
}


pub fn madd0(a: u64, b: u64, c: u64) -> u64 {
    let mut hi: u64;
    let mut lo: u128; // Using u128 to handle overflow from multiplication
    let mut carry: u64;

    // Perform the multiplication
    lo = (a as u128) * (b as u128);
    hi = (lo >> 64) as u64; // Extract the high 64 bits
    lo = lo & 0xFFFFFFFFFFFFFFFF; // Keep only the low 64 bits

    // Add c to the low part of the result
    let sum_with_c = (lo as u64).wrapping_add(c);
    carry = if sum_with_c < lo as u64 { 1 } else { 0 };

    // Add the carry to the high part of the result
    hi = hi.wrapping_add(carry);

    hi
}

pub fn madd2(a: u64, b: u64, c: u64, d: u64) -> (u64, u64) {
    let mut hi: u64;
    let mut lo: u128;  // Using u128 to handle overflow from multiplication
    let mut carry: u64;

    // Perform the multiplication
    lo = (a as u128) * (b as u128);
    hi = (lo >> 64) as u64; // Extract the high 64 bits
    lo = lo & 0xFFFFFFFFFFFFFFFF; // Keep only the low 64 bits

    // Add c and d
    let sum_cd = c.overflowing_add(d);
    let c = sum_cd.0;
    carry = if sum_cd.1 { 1 } else { 0 };

    // Add carry to high
    let add_carry_hi = hi.overflowing_add(carry);
    hi = add_carry_hi.0;

    // Add c to low and handle carry
    let add_c_lo = (lo as u64).overflowing_add(c);
    lo = add_c_lo.0 as u128;
    carry = if add_c_lo.1 { 1 } else { 0 };

    // Add carry to high again
    let add_carry_hi2 = hi.overflowing_add(carry);
    hi = add_carry_hi2.0;

    (hi, lo as u64)
}

#[test]
fn test_montgomery_reduce(){
    let inv = Fq::from(<Fr as PrimeField>::MODULUS).neg_in_place().inverse().unwrap();
    println!("{}", inv.0);
}
