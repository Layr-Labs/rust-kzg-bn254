use ark_bn254::Fq;
use ark_ff::PrimeField;

pub fn montgomery_reduce(z_0: &u64, z_1: &u64, z_2: &u64, z_3: &u64) -> (u64, u64, u64, u64) {
    let mut z0 = z_0.clone();
    let mut z1 = z_1.clone();
    let mut z2 = z_2.clone();
    let mut z3 = z_3.clone();
    let inv: u64 = 9786893198990664585;
    let modulus = <Fq as PrimeField>::MODULUS.0;

    let mut m: u64 = z0.wrapping_mul(inv);
    let mut c = madd0(m, modulus[0], z0);
    (c, z0) = madd2(m, modulus[1], z1, c);
    (c, z1) = madd2(m, modulus[2], z2, c);
    (c, z2) = madd2(m, modulus[3], z3, c);
    z3 = c;

    m = z0.wrapping_mul(inv);
    c = madd0(m, modulus[0], z0);
    (c, z0) = madd2(m, modulus[1], z1, c);
    (c, z1) = madd2(m, modulus[2], z2, c);
    (c, z2) = madd2(m, modulus[3], z3, c);
    z3 = c;

    m = z0.wrapping_mul(inv);
    c = madd0(m, modulus[0], z0);
    (c, z0) = madd2(m, modulus[1], z1, c);
    (c, z1) = madd2(m, modulus[2], z2, c);
    (c, z2) = madd2(m, modulus[3], z3, c);
    z3 = c;

    m = z0.wrapping_mul(inv);
    c = madd0(m, modulus[0], z0);
    (c, z0) = madd2(m, modulus[1], z1, c);
    (c, z1) = madd2(m, modulus[2], z2, c);
    (c, z2) = madd2(m, modulus[3], z3, c);
    z3 = c;

    let is_smaller_than_modulus = z3 < modulus[3]
        || (z3 == modulus[3]
            && (z2 < modulus[2]
                || (z2 == modulus[2]
                    && (z1 < modulus[1] || (z1 == modulus[1] && (z0 < modulus[0]))))));

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
    let (diff, _borrow_out1) = x.overflowing_sub(y);
    let (diff, _borrow_out2) = diff.overflowing_sub(borrow);

    // Calculate the final borrow out using bitwise operations
    // This replicates the bit logic in the original Go function
    let borrow_out = ((!x & y) | (!(x ^ y) & diff)) >> 63;

    (diff, borrow_out)
}

pub fn madd0(a: u64, b: u64, c: u64) -> u64 {
    let mut hi: u64;
    let mut lo: u128; // Using u128 to handle overflow from multiplication
    let carry: u64;

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
    let mut lo: u128; // Using u128 to handle overflow from multiplication
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

// pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
//     let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
//     (ret as u64, (ret >> 64) as u64)
// }

#[test]
fn test_montgomery_reduce() {
    use ark_bn254::Fr;
    use ark_ff::Field;

    let inv = Fq::from(<Fr as PrimeField>::MODULUS)
        .neg_in_place()
        .inverse()
        .unwrap();
    println!("{}", inv.0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use ark_ff::fields::PrimeField;

    #[test]
    fn test_montgomery_reduce_basic() {
        // Basic test case with small values
        let (z0, z1, z2, z3) = montgomery_reduce(&1_u64, &2_u64, &3_u64, &4_u64);
        let expected = (
            1015341533287961015,
            614227897398722093,
            10092218387357075792,
            2216689030230384375,
        ); // Expected values will depend on the actual function logic
        assert_eq!((z0, z1, z2, z3), expected);
    }

    #[test]
    fn test_montgomery_reduce_large_values() {
        // Test case with large values
        let (z0, z1, z2, z3) = montgomery_reduce(&u64::MAX, &u64::MAX, &u64::MAX, &u64::MAX);
        // Calculate the expected result based on the Montgomery reduction algorithm
        // This is an example, you need to calculate the correct expected values
        let expected = (
            5664406609643832081,
            12421288465352154260,
            16783890958096582019,
            143333441873369583,
        ); // Placeholder, update with correct values
        assert_eq!((z0, z1, z2, z3), expected);
    }

    #[test]
    fn test_montgomery_reduce_modulus() {
        // Test case where inputs are the modulus values
        let modulus = <Fq as PrimeField>::MODULUS.0;
        let (z0, z1, z2, z3) =
            montgomery_reduce(&modulus[0], &modulus[1], &modulus[2], &modulus[3]);
        let expected = (0, 0, 0, 0); // Result should be zero since we're reducing the modulus
        assert_eq!((z0, z1, z2, z3), expected);
    }

    #[test]
    fn test_montgomery_reduce_zero() {
        // Test case where all inputs are zero
        let (z0, z1, z2, z3) = montgomery_reduce(&0, &0, &0, &0);
        let expected = (0, 0, 0, 0);
        assert_eq!((z0, z1, z2, z3), expected);
    }

    #[test]
    fn test_montgomery_reduce_mixed_values() {
        // Test case with mixed values
        let (z0, z1, z2, z3) = montgomery_reduce(&1_u64, &0_u64, &u64::MAX, &2_u64);
        // Calculate the expected result based on the Montgomery reduction algorithm
        // This is an example, you need to calculate the correct expected values
        let expected = (
            3113359121765060147,
            13738305701328143478,
            16036157884190814464,
            3242762270701651436,
        ); // Placeholder, update with correct values
        assert_eq!((z0, z1, z2, z3), expected);
    }

    #[test]
    fn test_madd2_no_overflow() {
        // Case where there is no overflow in multiplication or addition
        let (hi, lo) = madd2(2, 3, 4, 5);
        assert_eq!(hi, 0);
        assert_eq!(lo, 6 + 9); // 2*3 + 4 + 5
    }

    #[test]
    fn test_madd2_with_multiplication_overflow() {
        // Case where multiplication overflows into high bits
        let (hi, lo) = madd2(u64::MAX, u64::MAX, 0, 0);
        assert_eq!(hi, u64::MAX - 1);
        assert_eq!(lo, 1); // (2^64-1)*(2^64-1) = 2^128-2^64+1
    }

    #[test]
    fn test_madd2_with_addition_overflow() {
        // Case where addition overflows
        let (hi, lo) = madd2(0, 0, u64::MAX, 1);
        assert_eq!(hi, 1);
        assert_eq!(lo, 0);
    }

    #[test]
    fn test_madd2_with_both_overflows() {
        // Case where both multiplication and addition overflow
        let (hi, lo) = madd2(u64::MAX, u64::MAX, u64::MAX, 1);
        assert_eq!(hi, u64::MAX);
        assert_eq!(lo, 1);
    }

    #[test]
    fn test_madd2_edge_case_zero_multiplication() {
        // Case where multiplication result is zero
        let (hi, lo) = madd2(0, 0, 123, 456);
        assert_eq!(hi, 0);
        assert_eq!(lo, 579);
    }

    #[test]
    fn test_madd2_edge_case_zero_addition() {
        // Case where addition result is zero
        let (hi, lo) = madd2(123, 456, 0, 0);
        assert_eq!(hi, 0);
        assert_eq!(lo, 123 * 456);
    }

    #[test]
    fn test_madd2_large_numbers() {
        // Case with large numbers to test boundary conditions
        let (hi, lo) = madd2(1 << 32, 1 << 32, u64::MAX - 1, 1);
        assert_eq!(hi, 1);
        assert_eq!(lo, u64::MAX);
    }

    #[test]
    fn test_madd2_all_ones() {
        // Case where all inputs are ones (u64::MAX)
        let (hi, lo) = madd2(u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(hi, u64::MAX);
        assert_eq!(lo, u64::MAX);
    }

    #[test]
    fn test_sub_64_no_borrow() {
        // Case where there is no borrow
        let (result, borrow_out) = sub_64(10, 5, 0);
        assert_eq!(result, 5);
        assert_eq!(borrow_out, 0);
    }

    #[test]
    fn test_sub_64_with_borrow() {
        // Case where there is an initial borrow
        let (result, borrow_out) = sub_64(10, 5, 1);
        assert_eq!(result, 4);
        assert_eq!(borrow_out, 0);
    }

    #[test]
    fn test_sub_64_with_borrow_out() {
        // Case where the subtraction causes a borrow
        let (result, borrow_out) = sub_64(5, 10, 0);
        assert_eq!(result, u64::MAX - 4);
        assert_eq!(borrow_out, 1);
    }

    #[test]
    fn test_sub_64_with_initial_borrow_and_borrow_out() {
        // Case where both the initial borrow and subtraction cause a borrow
        let (result, borrow_out) = sub_64(5, 10, 1);
        assert_eq!(result, u64::MAX - 5);
        assert_eq!(borrow_out, 1);
    }

    #[test]
    fn test_sub_64_max_values_no_borrow() {
        // Case with maximum values but no initial borrow
        let (result, borrow_out) = sub_64(u64::MAX, u64::MAX, 0);
        assert_eq!(result, 0);
        assert_eq!(borrow_out, 0);
    }

    #[test]
    fn test_sub_64_max_values_with_borrow() {
        // Case with maximum values and an initial borrow
        let (result, borrow_out) = sub_64(u64::MAX, u64::MAX, 1);
        assert_eq!(result, u64::MAX);
        assert_eq!(borrow_out, 1);
    }

    #[test]
    fn test_sub_64_zero_values() {
        // Case with zero values
        let (result, borrow_out) = sub_64(0, 0, 0);
        assert_eq!(result, 0);
        assert_eq!(borrow_out, 0);
    }

    #[test]
    fn test_sub_64_zero_values_with_borrow() {
        // Case with zero values and an initial borrow
        let (result, borrow_out) = sub_64(0, 0, 1);
        assert_eq!(result, u64::MAX);
        assert_eq!(borrow_out, 1);
    }

    #[test]
    fn test_sub_64_edge_case_overflow() {
        // Case where subtraction causes an overflow
        let (result, borrow_out) = sub_64(0, 1, 1);
        assert_eq!(result, u64::MAX - 1);
        assert_eq!(borrow_out, 1);
    }
}
