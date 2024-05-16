use ark_bn254::Fr;
use ark_std::Zero;
use crate::{ errors::PolynomialError, helpers};

#[derive(Clone, Debug)]
pub struct Polynomial {
    elements: Vec<Fr>,
    length_of_padded_blob: usize,
    length_of_padded_blob_as_fr_vector: usize
}

impl Polynomial {
    /// Constructs a new `Polynomial` with a given vector of `Fr` elements.
    pub fn new(elements: &Vec<Fr>, length_of_padded_blob: usize) -> Self {
        let mut padded_input_fr = vec![];
        for i in 0..elements.len().next_power_of_two() {
            if i < elements.len() {
                padded_input_fr.push(elements[i]);
            } else {
                padded_input_fr.push(Fr::zero());
            }
        }
        Polynomial { elements: padded_input_fr, length_of_padded_blob, length_of_padded_blob_as_fr_vector: elements.len() }
    }

    /// Returns the number of elements in the polynomial.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn get_at_index(&self, i: usize) -> Option<&Fr> {
        self.elements.get(i)
    }

    /// Checks if the polynomial has no elements.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Converts all `Fr` elements in the `Polynomial` to a single byte vector.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        helpers::to_byte_array(&self.elements, self.length_of_padded_blob)
    }

    /// Evaluates the polynomial at a given point using Horner's method.
    pub fn eval(&self, point: &Fr) -> Fr {
        self.elements.iter().rev().fold(Fr::zero(), |acc, &coeff| {
            (acc * point) + &coeff
        })
    }

    /// Returns a clone of the elements as a `Vec<Fr>`.
    pub fn to_vec(&self) -> Vec<Fr> {
        self.elements.clone()
    }

    /// Constructs a `Polynomial` from a list of string representations of `Fr` elements. Cannot be used to decode data without original length.
    pub fn from_str(str_list: Vec<&str>, length_of_padded_blob: usize, length_of_padded_blob_as_fr_vector: usize) -> Result<Self, PolynomialError> {
        let fr_list: Vec<Fr> = str_list.iter().map(|s| s.parse().map_err(|_| PolynomialError::SerializationFromStringError)).collect::<Result<_, _>>()?;
        Ok(Polynomial { elements: fr_list, length_of_padded_blob, length_of_padded_blob_as_fr_vector })
    }

    /// Returns the degree of the polynomial.
    pub fn degree(&self) -> usize {
        if self.is_empty() {
            0
        } else {
            self.elements.len() - 1
        }
    }
}

#[test]
fn test_to_fr_array(){
    use crate::{blob::Blob, consts::GETTYSBURG_ADDRESS_BYTES};
    let mut blob = Blob::from_bytes_and_pad(vec![42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27, 116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40].as_slice());    
    let poly = blob.to_polynomial().unwrap();
    assert_eq!(poly.to_bytes_be(), blob.get_blob_data(), "should be deserialized properly");

    blob.remove_padding().unwrap(); 
    assert_eq!(blob.get_blob_data(), vec![42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27, 116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40],  "should be deserialized properly");
   
    let mut long_blob = Blob::from_bytes_and_pad(GETTYSBURG_ADDRESS_BYTES);
    let long_poly = long_blob.to_polynomial().unwrap();
    // let ga_converted_fr = to_fr_array(&ga_converted);
    assert_eq!(long_blob.get_blob_data(), long_poly.to_bytes_be(),  "should be deserialized properly");
    long_blob.remove_padding().unwrap();
    assert_eq!(long_blob.get_blob_data(), GETTYSBURG_ADDRESS_BYTES,  "should be deserialized properly");


}
