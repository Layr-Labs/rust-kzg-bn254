use std::{fmt, io};
use std::fs::File;
use std::io::BufReader;
use crossbeam_channel::{bounded, Receiver, Sender};

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, LegendreSymbol, PrimeField};
use ark_serialize::{CanonicalSerialize, Read};
use ark_std::ops::{Div, Mul};
use ark_std::{One, Zero};
use ark_std::str::FromStr;
use num_traits::ToPrimitive;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use crate::blob::Blob;
use crate::consts::BYTES_PER_FIELD_ELEMENT;
use crate::errors::KzgError;
use crate::polynomial::Polynomial;
use crate::traits::ReadPointFromBytes;
use crate::{arith, new_helpers as helpers};

use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

pub struct Kzg {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    params: Params,
    srs_order: u64,
    expanded_roots_of_unity: Vec<Fr>
}

struct Params {
    chunk_length: u64,
    num_chunks: u64,
    max_fft_width: u64,
    completed_setup: bool,
}

impl Kzg {
    
    pub fn setup(path_to_g1_points: &str, path_to_g2_points: &str, srs_order: u32) -> Result<Self, KzgError> {

        let g1_points = Self::parallel_read_g1_points(path_to_g1_points.to_owned()).unwrap();
        let g2_points = Self::parallel_read_g2_points(path_to_g2_points.to_owned()).unwrap();

        Ok(Self{
            g1: g1_points,
            g2: g2_points,
            params:  Params {
                chunk_length: 0,
                num_chunks: 0,
                max_fft_width: 0,
                completed_setup: false,
            },
            srs_order: srs_order.into(),
            expanded_roots_of_unity: vec![]
        })

    }

    pub fn data_setup_custom(&mut self, num_of_nodes: u64, padded_input_data_size: u64) -> Result<(), KzgError>{

        let len_of_data_in_elements = padded_input_data_size / u64::try_from(BYTES_PER_FIELD_ELEMENT).unwrap();
        let min_num_chunks = len_of_data_in_elements / num_of_nodes;
        self.data_setup_mins(min_num_chunks, num_of_nodes)
    }

    pub fn data_setup_mins(&mut self, min_num_chunks: u64, min_chunk_length: u64) -> Result<(), KzgError>{
        
        let mut params = Params {
            num_chunks: min_num_chunks.next_power_of_two(),
            chunk_length: min_chunk_length.next_power_of_two(),
            max_fft_width: 0_u64,
            completed_setup: false,
        };

        // now setup fft
        let number_of_evaluations = (params.chunk_length * params.num_chunks).to_u8().unwrap();
        params.max_fft_width = 1_u64 << number_of_evaluations;
        let mut log2_of_evals = number_of_evaluations.to_f64().unwrap().log2().to_u8().unwrap();


        if params.chunk_length == 1 {
            log2_of_evals = (2 * params.num_chunks).to_f64().unwrap().log2().to_u8().unwrap();
        }

        if params.chunk_length * params.num_chunks >= self.srs_order {
            return Err(KzgError::SerializationError("the supplied encoding parameters are not valid with respect to the SRS.".to_string()));
        }

        let primitive_roots_of_unity = Self::get_primitive_roots_of_unity();
        let found_root_of_unity = primitive_roots_of_unity.get(log2_of_evals.to_usize().unwrap()).unwrap();
        let expanded_roots_of_unity = Self::expand_root_of_unity(found_root_of_unity);
        
        params.completed_setup = true;
        self.params = params;
        self.expanded_roots_of_unity = expanded_roots_of_unity;

        Ok(())
    }

    fn expand_root_of_unity(root_of_unity: &Fr) -> Vec<Fr> {
        let mut roots = vec![Fr::one()];  // Initialize with 1
        roots.push(*root_of_unity);       // Add the root of unity
    
        let mut i = 1;
        while !roots[i].is_one() {  // Continue until the element cycles back to one
            let this = &roots[i];
            i += 1;
            roots.push(this * root_of_unity);  // Push the next power of the root of unity
        }
        roots
    }

    fn get_primitive_roots_of_unity() -> Vec<Fr> {
        let data: [&str; 29] = [
            "1",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "14940766826517323942636479241147756311199852622225275649687664389641784935947",
            "4419234939496763621076330863786513495701855246241724391626358375488475697872",
            "9088801421649573101014283686030284801466796108869023335878462724291607593530",
            "10359452186428527605436343203440067497552205259388878191021578220384701716497",
            "3478517300119284901893091970156912948790432420133812234316178878452092729974",
            "6837567842312086091520287814181175430087169027974246751610506942214842701774",
            "3161067157621608152362653341354432744960400845131437947728257924963983317266",
            "1120550406532664055539694724667294622065367841900378087843176726913374367458",
            "4158865282786404163413953114870269622875596290766033564087307867933865333818",
            "197302210312744933010843010704445784068657690384188106020011018676818793232",
            "20619701001583904760601357484951574588621083236087856586626117568842480512645",
            "20402931748843538985151001264530049874871572933694634836567070693966133783803",
            "421743594562400382753388642386256516545992082196004333756405989743524594615",
            "12650941915662020058015862023665998998969191525479888727406889100124684769509",
            "11699596668367776675346610687704220591435078791727316319397053191800576917728",
            "15549849457946371566896172786938980432421851627449396898353380550861104573629",
            "17220337697351015657950521176323262483320249231368149235373741788599650842711",
            "13536764371732269273912573961853310557438878140379554347802702086337840854307",
            "12143866164239048021030917283424216263377309185099704096317235600302831912062",
            "934650972362265999028062457054462628285482693704334323590406443310927365533",
            "5709868443893258075976348696661355716898495876243883251619397131511003808859",
            "19200870435978225707111062059747084165650991997241425080699860725083300967194",
            "7419588552507395652481651088034484897579724952953562618697845598160172257810",
            "2082940218526944230311718225077035922214683169814847712455127909555749686340",
            "19103219067921713944291392827692070036145651957329286315305642004821462161904"
        ];
        data.iter().map(|each| Fr::from_str(each).unwrap()).collect()
    }

    pub fn get_g1_points(&self) -> Vec<G1Affine> {
        self.g1.to_vec()
    }

    fn read_file_chunks(file_path: &str, sender: Sender<(Vec<u8>, usize)>, point_size: usize) -> io::Result<()> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut position = 0;
        let mut buffer = vec![0u8; point_size];
    
        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            sender.send((buffer[..bytes_read].to_vec(), position)).unwrap();
            position += bytes_read;
            buffer.resize(point_size, 0); // Ensure the buffer is always the correct size
        }
    
        Ok(())
    }

    fn process_chunks<T>(receiver: Receiver<(Vec<u8>, usize)>) -> Vec<(T, usize)>
    where
        T: ReadPointFromBytes,
    {
        receiver.iter().filter_map(|(chunk, position)| {
            match T::read_point_from_bytes_be(&chunk) {
                Ok(point) => Some((point, position)),
                Err(_) => None,  // Handle error, possibly log or return Err if needed
            }
        }).collect()
    }

    pub fn parallel_read_g2_points(file_path: String) -> Result<Vec<G2Affine>, KzgError> {

        let (sender, receiver) = bounded::<(Vec<u8>, usize)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(move || {
            if let Err(e) = Self::read_file_chunks(&file_path, sender, 64) {
                eprintln!("Error reading file: {}", e);
            }
        });

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers).map(|_| {
            let receiver = receiver.clone();
            std::thread::spawn(move || {
                Self::process_chunks::<G2Affine>(receiver)
            })
        }).collect();

        // Wait for the reader thread to finish
        reader_thread.join().expect("Reader thread panicked");

        // Collect and sort results
        let mut all_points = Vec::new();
        for worker in workers {
            let points = worker.join().expect("Worker thread panicked");
            all_points.extend(points);
        }

        // Sort by original position to maintain order
        all_points.sort_by_key(|&(_, position)| position);
        Ok(all_points.iter().map(|(point, _)| *point).collect())

    }


    pub fn parallel_read_g1_points(file_path: String) -> Result<Vec<G1Affine>, KzgError> {

        let (sender, receiver) = bounded::<(Vec<u8>, usize)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(move || {
            if let Err(e) = Self::read_file_chunks(&file_path, sender, 32) {
                eprintln!("Error reading file: {}", e);
            }
        });

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers).map(|_| {
            let receiver = receiver.clone();
            std::thread::spawn(move || {
                Self::process_chunks::<G1Affine>(receiver)
            })
        }).collect();

        // Wait for the reader thread to finish
        reader_thread.join().expect("Reader thread panicked");

        // Collect and sort results
        let mut all_points = Vec::new();
        for worker in workers {
            let points = worker.join().expect("Worker thread panicked");
            all_points.extend(points);
        }

        // Sort by original position to maintain order
        all_points.sort_by_key(|&(_, position)| position);

        Ok(all_points.iter().map(|(point, _)| *point).collect())

    }



    pub fn get_g2_points(&self) -> Vec<G2Affine> {
        self.g2.to_vec()
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
        let polynomial: Polynomial = match blob.to_polynomial() {
            Ok(poly) => poly,
            Err(error) => return Err(KzgError::SerializationError(error.to_string())),
        };

        let commitment = self.commit(&polynomial, Some(4))?;
        let mut compressed_bytes = Vec::new();
        match commitment.serialize_compressed(&mut compressed_bytes) {
            Ok(_) => Ok(compressed_bytes),
            Err(err) => Err(KzgError::SerializationError(err.to_string())),
        }
    }

    pub fn compute_kzg_proof_with_roots_of_unity(&self, polynomial: &Polynomial, index: u64, padded_input: Polynomial) -> Result<G1Affine, KzgError>{
        self.compute_kzg_proof(polynomial, index, &self.expanded_roots_of_unity, padded_input.len())
    }

    pub fn compute_kzg_proof(&self, polynomial: &Polynomial, index: u64, root_of_unities: &Vec<Fr>, padded_input_length: usize) -> Result<G1Affine, KzgError> {
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
        
        let g1_lagrange = self.g1_ifft(padded_input_length)?;

        match G1Projective::msm(&g1_lagrange, &quotient_poly) {
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

    pub fn g1_ifft(&self, length: usize) -> Result<Vec<G1Affine>, KzgError>{

        // is not power of 2
        if !length.is_power_of_two() {
            return Err(KzgError::FftError("length provided is not a power of 2".to_string()));
        }

        let domain = GeneralEvaluationDomain::<Fr>::new(length).expect("Failed to construct domain for IFFT");
        let points_projective: Vec<G1Projective> = self.g1[..length].iter().map(|&p| G1Projective::from(p)).collect();
        
        // Perform the IFFT
        let ifft_result = domain.ifft(&points_projective);

        let ifft_result_affine: Vec<_> = ifft_result.iter().map(|p| p.into_affine()).collect();
        Ok(ifft_result_affine)
    }
    
}

#[test]
fn test_g1_ifft(){
    use std::io::BufRead;

    let file = File::open("src/test-files/lagrangeG1SRS.txt").unwrap();
    let reader = BufReader::new(file);
    
    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        3000
    ).unwrap();

    let kzg_g1_points = kzg.g1_ifft(64).unwrap();

    // Iterate over each line in the file
    for (i, line_result) in reader.lines().enumerate() {
        let mut line = line_result.unwrap();  // Retrieve the line, handling potential I/O errors
        line = line.trim_end().to_string();

        // Split the line at each comma and process the parts
        let parts: Vec<&str> = line.split(',').collect();
        
        let x = Fq::from_str(parts[0]).expect("should be fine");
        let y = Fq::from_str(parts[1]).expect("should be fine");

        let point = G1Affine::new_unchecked(x, y);
        assert_eq!(point, kzg_g1_points[i], "failed on {i}");
    }

}

#[test]
fn test_read_g1_point_from_bytes_be(){

    use ark_std::str::FromStr;
    use std::io::BufRead;
    use std::time::Instant;
    
    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        3000
    ).unwrap();


    let file = File::open("src/test-files/srs.g1.points.string").unwrap();
    let reader = BufReader::new(file);
    let kzg_g1_points = kzg.get_g1_points();

    // Iterate over each line in the file
    for (i, line_result) in reader.lines().enumerate() {
        let mut line = line_result.unwrap();  // Retrieve the line, handling potential I/O errors
        line = line.trim_end().to_string();

        // Split the line at each comma and process the parts
        let parts: Vec<&str> = line.split(',').collect();
        
        let x = Fq::from_str(parts[0]).expect("should be fine");
        let y = Fq::from_str(parts[1]).expect("should be fine");

        let point = G1Affine::new_unchecked(x, y);
        assert_eq!(point, kzg_g1_points[i]);
    }

}

#[test]
fn test_read_g2_point_from_bytes_be(){

    use ark_std::str::FromStr;
    use std::io::BufRead;

    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        3000
    ).unwrap();

    let file = File::open("src/test-files/srs.g2.points.string").unwrap();
    let reader = BufReader::new(file);
    let kzg_g2_points = kzg.get_g2_points();

    let mut custom_points_list: usize = 0;
    // Iterate over each line in the file
    for (i, line_result) in reader.lines().enumerate() {
        let mut line = line_result.unwrap();  // Retrieve the line, handling potential I/O errors
        line = line.trim_end().to_string();

        let parts: Vec<&str> = line.split(',').collect();
        
        let x_c0 = Fq::from_str(parts[0]).expect("should be fine");
        let x_c1 = Fq::from_str(parts[1]).expect("should be fine");

        let y_c0 = Fq::from_str(parts[2]).expect("should be fine");
        let y_c1 = Fq::from_str(parts[3]).expect("should be fine");

        let x = Fq2::new(x_c0, x_c1);
        let y = Fq2::new(y_c0, y_c1);
        let point = G2Affine::new_unchecked(x, y);
        custom_points_list+=1;
        assert_eq!(point, kzg_g2_points[i]);
    }
    assert_eq!(custom_points_list, kzg_g2_points.len());

}
