use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::BufReader;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, LegendreSymbol, PrimeField};
use ark_serialize::{CanonicalSerialize, Read};
use ark_std::ops::{Div, Mul, Sub};
use ark_std::{Zero, One};
use num_traits::ToPrimitive;
use crate::blob::Blob;
use crate::polynomial::Polynomial;
use crate::{arith, new_helpers as helpers};

pub struct Kzg {
    pub g1: Vec<G1Affine>,
    pub g1_lagrange: Vec<G1Affine>,
    pub g2: Vec<G1Affine>,
    pub g2_next_pow_2: Vec<G1Affine>
}

#[derive(Debug)]
pub enum KzgError {
    CommitError(String),
    SerializationError(String)
}

impl fmt::Display for KzgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            KzgError::CommitError(ref msg) => write!(f, "Commitment error: {}", msg),
            KzgError::SerializationError(ref msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl Error for KzgError {}

impl Kzg {
    
    pub fn setup(path_to_g1_points: &str, path_to_g2_points: &str) -> Result<(), KzgError>{
        
        let g1_points_file = File::open(path_to_g1_points).expect("unable to read g1 points path");
        let g2_points_file = File::open(path_to_g2_points).expect("unable to read g2 points path");

        let mut g1_points_reader = BufReader::new(g1_points_file);
        let mut g2_points_reader = BufReader::new(g2_points_file);
        let mut g1_buffer = [0u8; 32];
        let mut g2_buffer = [0u8; 64];

        let mut g1_points: Vec<G1Affine> = vec![];
        let mut g2_points: Vec<G2Affine> = vec![];

        loop {
            // Read exactly 32 bytes
            let n = g1_points_reader.read(&mut g1_buffer[..]).expect("problem reading buffer");
            if n == 0 {
                break; // Break if we've reached the end of the file
            }
            g1_points.push(Self::read_g1_point_from_bytes_be(&g1_buffer[..n].to_vec())?);
        }

        loop {
            // Read exactly 32 bytes
            let n = g2_points_reader.read(&mut g2_buffer[..]).expect("problem reading buffer");
            if n == 0 {
                break; // Break if we've reached the end of the file
            }
            g2_points.push(Self::read_g2_point_from_bytes_be(&g2_buffer[..n].to_vec())?);
        }

        Ok(())
    }

    const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
        let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
        (ret as u64, (ret >> 64) as u64)
    }

    #[inline(always)]
    

    pub fn lexicographically_largest(z: &Fq) -> bool {
        // This can be determined by checking to see if the element is
        // larger than (p - 1) // 2. If we subtract by ((p - 1) // 2) + 1
        // and there is no underflow, then the element must be larger than
        // (p - 1) // 2.

        // First, because self is in Montgomery form we need to reduce it
        let tmp = arith::montgomery_reduce(&z.0.0[0], &z.0.0[1], &z.0.0[2], &z.0.0[3]);
        let mut borrow: u64;

        (_, borrow) = Self::sbb(tmp.0, 0x9E10460B6C3E7EA4, 0);
        (_, borrow) = Self::sbb(tmp.1, 0xCBC0B548B438E546, borrow);
        (_, borrow) = Self::sbb(tmp.2, 0xDC2822DB40C0AC2E, borrow);
        (_, borrow) = Self::sbb(tmp.3, 0x183227397098D014, borrow);

        // If the element was smaller, the subtraction will underflow
        // producing a borrow value of 0xffff...ffff, otherwise it will
        // be zero. We create a Choice representing true if there was
        // overflow (and so this element is not lexicographically larger
        // than its negation) and then negate it.

        borrow == 0
    }

    

    fn read_g2_point_from_bytes_be(g2_bytes_be: &Vec<u8>) -> Result<G2Affine, KzgError>{
        let m_mask: u8 = 0b11 << 6;
        let m_compressed_infinity: u8 = 0b01 << 6;
        let m_compressed_smallest: u8 = 0b10 << 6;
	    let m_compressed_largest: u8 = 0b11 << 6;
        
        let m_data = g2_bytes_be[0] & m_mask;
    
        if m_data == m_compressed_infinity {
            if !helpers::is_zeroed(g2_bytes_be[0] & !m_mask, g2_bytes_be[1..64].to_vec()) {
                KzgError::SerializationError("point at infinity not coded properly for g2".to_string());
            }
            return Ok(G2Affine::zero());
        }
        
        let mut x_bytes = [0u8; 64];
        x_bytes.copy_from_slice(g2_bytes_be);
        x_bytes[0] &= !m_mask;

        let c1 = Fq::from_be_bytes_mod_order(&x_bytes[..32]);
        let c0 = Fq::from_be_bytes_mod_order(&x_bytes[32..]);
        let x = Fq2::new(c0, c1);
        let y_squared = x*x*x;

        let twist_c0 = Fq::from(9);
        let twist_c1 = Fq::from(1);

        // this is bTwistCurveCoeff
        let mut twist_curve_coeff = Fq2::new(twist_c0, twist_c1);
        twist_curve_coeff = *twist_curve_coeff.inverse_in_place().unwrap();

        twist_curve_coeff.c0 = twist_curve_coeff.c0 * Fq::from(3);
        twist_curve_coeff.c1 = twist_curve_coeff.c1 * Fq::from(3);

        let added_result = y_squared + twist_curve_coeff;
        if added_result.legendre() == LegendreSymbol::QuadraticNonResidue {
            return Err(KzgError::SerializationError("invalid compressed coordinate: square root doesn't exist".to_string()));
        }

        let mut y_sqrt = added_result.sqrt().ok_or("no square root found").unwrap();
        
        let mut lexicographical_check_result = false;

        if y_sqrt.c1.0.is_zero() {
            lexicographical_check_result = Self::lexicographically_largest(&y_sqrt.c0);
        } else {
            lexicographical_check_result = Self::lexicographically_largest(&y_sqrt.c1);
        }

        if lexicographical_check_result {
            if m_data == m_compressed_smallest {
                y_sqrt.neg_in_place();
            }
        } else {
            if m_data == m_compressed_largest {
                y_sqrt.neg_in_place();
            }
        }

        
        let point = G2Affine::new_unchecked(x, y_sqrt);
        if !point.is_in_correct_subgroup_assuming_on_curve(){
            return Err(KzgError::SerializationError("point couldn't be created".to_string()));
        }
        Ok(point)
    }

    fn read_g1_point_from_bytes_be(g1_bytes_be: &Vec<u8>) -> Result<G1Affine, KzgError>{
        let m_mask: u8 = 0b11 << 6;
        let m_compressed_infinity: u8 = 0b01 << 6;
        let m_compressed_smallest: u8 = 0b10 << 6;
	    let m_compressed_largest: u8 = 0b11 << 6;
        
        let m_data = g1_bytes_be[0] & m_mask;
    
        if m_data == m_compressed_infinity {
            if !helpers::is_zeroed(g1_bytes_be[0] & !m_mask, g1_bytes_be[1..32].to_vec()) {
                KzgError::SerializationError("point at infinity not coded properly for g1".to_string());
            }
            return Ok(G1Affine::zero());
        }
        
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(g1_bytes_be);
        x_bytes[0] &= !m_mask;
        let x = Fq::from_be_bytes_mod_order(&x_bytes);
        let y_squared = x*x*x + Fq::from(3);
        let mut y_sqrt = y_squared.sqrt().ok_or("no item1").unwrap();
    
        if Self::lexicographically_largest(&y_sqrt) {
            if m_data == m_compressed_smallest {
                y_sqrt.neg_in_place();
            }
        } else {
            if m_data == m_compressed_largest {
                y_sqrt.neg_in_place();
            }
        }
        let point = G1Affine::new_unchecked(x, y_sqrt);
        if !point.is_in_correct_subgroup_assuming_on_curve(){
            return Err(KzgError::SerializationError("point couldn't be created".to_string()));
        }
        Ok(point)
    }

    fn commit(&self, polynomial: &Polynomial, nb_tasks: Option<usize>) -> Result<G1Affine, KzgError> {
        if polynomial.is_empty() || polynomial.len() > self.g1.len() {
            return Err(KzgError::SerializationError("polynomial length is not correct".to_string()));
        }
    
        // Configure multi-threading
        let config = if let Some(n) = nb_tasks {
            rayon::ThreadPoolBuilder::new().num_threads(n).build().unwrap()
        } else {
            rayon::ThreadPoolBuilder::new().build().unwrap() // Use default configuration
        };
    
        // Perform the multi-exponentiation
        config.install(|| {
            let bases = &self.g1[..polynomial.len()];
            match G1Projective::msm(bases, &polynomial.to_vec()) {
                Ok(res) => Ok(res.into_affine()),
                Err(err) => Err(KzgError::CommitError(err.to_string())),
            }
        })
    }

    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> Result<Vec<u8>, KzgError> {
        let polynomial: Polynomial = blob.to_polynomial();
        let commitment = self.commit(&polynomial, Some(4))?;
        let mut compressed_bytes = Vec::new();
        match commitment.serialize_compressed(&mut compressed_bytes) {
            Ok(res) => Ok(compressed_bytes),
            Err(err) => Err(KzgError::SerializationError(err.to_string())),
        }
        
    }

    pub fn compute_kzg_proof(&self, polynomial: &Polynomial, index: u64, root_of_unities: &Vec<Fr>) -> Result<G1Affine, KzgError> {
        if polynomial.len() != root_of_unities.len() {
            panic!("inconsistent length between blob and root of unities");
        }
    
        let eval_fr = polynomial.to_vec();
        let mut poly_shift: Vec<Fr> = Vec::with_capacity(eval_fr.len());
        let usized_index = index.to_usize();
        let usized_index = if let Some(x) = index.to_usize() {
            x
        } else {
            return Err(KzgError::SerializationError("index couldn't be converted to usize".to_string()))
        };

        let value_fr = eval_fr[usized_index];
        let z_fr = root_of_unities[usized_index];
    
        for i in 0..eval_fr.len() {
            poly_shift.push(eval_fr[i] - value_fr);
        }
    
        let mut denom_poly = Vec::<Fr>::with_capacity(root_of_unities.len());
        for i in 0..eval_fr.len() {
            denom_poly.push(root_of_unities[i] - z_fr);
        }
    
        let mut quotient_poly = Vec::<Fr>::with_capacity(root_of_unities.len());
    
        for i in 0..root_of_unities.len() {
            if denom_poly[i].is_zero() {
                quotient_poly.push(self.compute_quotient_eval_on_domain(z_fr, &eval_fr, value_fr, &root_of_unities));
            } else {
                quotient_poly.push(poly_shift[i].div(denom_poly[i]));
            }
        }
    
        match G1Projective::msm(&self.g1_lagrange, &quotient_poly) {
            Ok(res) => Ok(G1Affine::from(res)),
            Err(err) => Err(KzgError::SerializationError(err.to_string())),
        }
    }

    fn compute_quotient_eval_on_domain(&self, z_fr: Fr, eval_fr: &Vec<Fr>, value_fr: Fr, roots_of_unities: &Vec<Fr>) -> Fr {

        let mut quotient = Fr::zero();
        let mut f_i = Fr::zero();
        let mut numerator = Fr::zero();
        let mut denominator = Fr::zero(); 
        let mut temp = Fr::zero();
    
        for i in 0..roots_of_unities.len() {
            let omega_i = roots_of_unities[i];
            if omega_i == z_fr {
                continue
            }
            f_i = eval_fr[i] - value_fr;
            numerator = f_i.mul(omega_i);
            denominator = z_fr - omega_i;
            denominator = denominator * z_fr;
            temp = numerator.div(denominator);
            quotient = quotient + temp;
    
        }
        quotient
    }
}

#[test]
fn test_read_g1_point_from_bytes_be(){
        // let resp = Kzg::read_g1_point_from_bytes_be(&vec![156, 221, 100, 72, 159, 129, 55, 89, 93, 152, 165, 183, 192, 253, 159, 1, 146, 191, 162, 196, 19, 162, 159, 59, 147, 61, 117, 169, 97, 128, 132, 202]);
        // println!("{:?}", resp);

        let resp2 = Kzg::read_g2_point_from_bytes_be(&vec![194,23,72,51,122,73,76,126,207,44,157,56,77,145,20,219,119,130,123,178,42,52,117,210,187,243,87,104,188,186,205,136,42,32,89,224,219,228,235,252,241,107,117,169,250,58,28,203,234,40,172,227,209,52,62,163,142,241,197,66,104,90,119,69]);
        println!("{:?}", resp2);
}
