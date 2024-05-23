use std::io;
use std::fs::File;
use std::io::BufReader;
use ark_bn254::g1::G1Affine;
use ark_ec::pairing::Pairing;
use crossbeam_channel::{bounded, Sender};
use ark_bn254::{Bn254, Fr, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_serialize::Read;
use ark_std::ops::{Div, Mul};
use ark_std::{One, Zero};
use ark_std::str::FromStr;
use num_traits::ToPrimitive;
use crate::blob::Blob;
use crate::consts::BYTES_PER_FIELD_ELEMENT;
use crate::errors::KzgError;
use crate::helpers;
use crate::polynomial::Polynomial;
use crate::traits::ReadPointFromBytes;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

#[derive(Debug, PartialEq)]
pub struct Kzg {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    params: Params,
    srs_order: u64,
    expanded_roots_of_unity: Vec<Fr>
}

#[derive(Debug, PartialEq)]
struct Params {
    chunk_length: u64,
    num_chunks: u64,
    max_fft_width: u64,
    completed_setup: bool,
}


impl Kzg {
    
    pub fn setup(path_to_g1_points: &str, path_to_g2_points: &str, g2_power_of2_path: &str, srs_order: u32, srs_points_to_load: u32) -> Result<Self, KzgError> {

        if srs_points_to_load > srs_order {
            return Err(KzgError::GenericError("number of points to load is more than the srs order".to_string()));
        }

        let g1_points = Self::parallel_read_g1_points(path_to_g1_points.to_owned(), srs_points_to_load).map_err(|e| KzgError::SerializationError(e.to_string()))?;
        let mut g2_points: Vec<G2Affine> = vec![];
        if !path_to_g2_points.is_empty() {
            g2_points = Self::parallel_read_g2_points(path_to_g2_points.to_owned(), srs_points_to_load).map_err(|e| KzgError::SerializationError(e.to_string()))?;
        } else if !g2_power_of2_path.is_empty() {
            g2_points = Self::read_g2_point_on_power_of_2(&g2_power_of2_path)?;
        } else {
            return Err(KzgError::GenericError("both g2 point files are empty, need the proper file specified".to_string()));
        }
        
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

    pub fn read_g2_point_on_power_of_2(g2_power_of2_path: &str) -> Result<Vec<G2Affine>, KzgError>{

        let mut file = File::open(g2_power_of2_path).unwrap();

        // Calculate the start position in bytes and seek to that position
        // Read in 64-byte chunks
        let mut chunks = Vec::new();
        let mut buffer = [0u8; 64];
        loop {
            let bytes_read = file.read(&mut buffer).unwrap();
            if bytes_read == 0 {
                break; // End of file reached
            }
            chunks.push(G2Affine::read_point_from_bytes_be(&buffer[..bytes_read].to_vec()).unwrap());
        }
        Ok(chunks)
    }

    /// data_setup_custom is a helper function
    pub fn data_setup_custom(&mut self, num_of_nodes: u64, padded_input_data_size: u64) -> Result<(), KzgError>{
        let floor = u64::try_from(BYTES_PER_FIELD_ELEMENT).map_err(|e| KzgError::SerializationError(e.to_string()))?;
        let len_of_data_in_elements = padded_input_data_size.div_ceil(floor);
        let min_num_chunks = len_of_data_in_elements.div_ceil(num_of_nodes);
        self.data_setup_mins(min_num_chunks, num_of_nodes)
    }

    ///data_setup_mins sets up the environment per the blob data
    pub fn data_setup_mins(&mut self, min_chunk_length: u64, min_num_chunks: u64) -> Result<(), KzgError>{
        
        let mut params = Params {
            num_chunks: min_num_chunks.next_power_of_two(),
            chunk_length: min_chunk_length.next_power_of_two(),
            max_fft_width: 0_u64,
            completed_setup: false,
        };

        let number_of_evaluations = params.chunk_length * params.num_chunks;
        let mut log2_of_evals = number_of_evaluations.to_f64().unwrap().log2().to_u8().unwrap();
        params.max_fft_width = 1_u64 << log2_of_evals;


        if params.chunk_length == 1 {
            log2_of_evals = (2 * params.num_chunks).to_f64().unwrap().log2().to_u8().unwrap();
        }

        if params.chunk_length * params.num_chunks >= self.srs_order {
            return Err(KzgError::SerializationError("the supplied encoding parameters are not valid with respect to the SRS.".to_string()));
        }

        let primitive_roots_of_unity = Self::get_primitive_roots_of_unity();
        let found_root_of_unity = primitive_roots_of_unity.get(log2_of_evals.to_usize().unwrap()).unwrap();
        let mut expanded_roots_of_unity = Self::expand_root_of_unity(found_root_of_unity);
        expanded_roots_of_unity.truncate(expanded_roots_of_unity.len()-1);
        
        params.completed_setup = true;
        self.params = params;
        self.expanded_roots_of_unity = expanded_roots_of_unity;

        Ok(())
    }

    /// helper function to get the 
    pub fn get_nth_root_of_unity(&self, i: usize) -> Option<&Fr> {
        self.expanded_roots_of_unity.get(i)
    }

    ///function to expand the roots based on the configuration
    fn expand_root_of_unity(root_of_unity: &Fr) -> Vec<Fr> {
        let mut roots = vec![Fr::one()];  // Initialize with 1
        roots.push(*root_of_unity); // Add the root of unity
    
        let mut i = 1;
        while !roots[i].is_one() { // Continue until the element cycles back to one
            let this = &roots[i];
            i += 1;
            roots.push(this * root_of_unity); // Push the next power of the root of unity
        }
        roots
    }

    /// refer to DA code for more context
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

    /// helper function to get g1 points 
    pub fn get_g1_points(&self) -> Vec<G1Affine> {
        self.g1.to_vec()
    }

    /// read files in chunks with specified length
    fn read_file_chunks(file_path: &str, sender: Sender<(Vec<u8>, usize)>, point_size: usize, num_points: u32) -> io::Result<()> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut position = 0;
        let mut buffer = vec![0u8; point_size];
        
        let mut i = 0;
        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            sender.send((buffer[..bytes_read].to_vec(), position)).unwrap();
            position += bytes_read;
            buffer.resize(point_size, 0); // Ensure the buffer is always the correct size
            i+=1;
            if num_points == i {
                break;
            }
        }
        Ok(())
    }

    /// read G2 points in parallel
    pub fn parallel_read_g2_points(file_path: String, srs_order: u32) -> Result<Vec<G2Affine>, KzgError> {

        let (sender, receiver) = bounded::<(Vec<u8>, usize)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(move || {
            if let Err(e) = Self::read_file_chunks(&file_path, sender, 64, srs_order) {
                eprintln!("Error reading file: {}", e);
            }
        });

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers).map(|_| {
            let receiver = receiver.clone();
            std::thread::spawn(move || {
                helpers::process_chunks::<G2Affine>(receiver)
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

    /// read G1 points in parallel
    pub fn parallel_read_g1_points(file_path: String, srs_order: u32) -> Result<Vec<G1Affine>, KzgError> {

        let (sender, receiver) = bounded::<(Vec<u8>, usize)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(move || {
            if let Err(e) = Self::read_file_chunks(&file_path, sender, 32, srs_order) {
                eprintln!("Error reading file: {}", e);
            }
        });

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers).map(|_| {
            let receiver = receiver.clone();
            std::thread::spawn(move || {
                helpers::process_chunks::<G1Affine>(receiver)
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

    /// obtain copy of g2 points
    pub fn get_g2_points(&self) -> Vec<G2Affine> {
        self.g2.to_vec()
    }

    /// commit the actual polynomial with the values setup
    fn commit(&self, polynomial: &Polynomial) -> Result<G1Affine, KzgError> {
        if polynomial.len() > self.g1.len() {
            return Err(KzgError::SerializationError("polynomial length is not correct".to_string()));
        }
    
        // Configure multi-threading
        let config = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get()).build().
        map_err(|err| KzgError::CommitError(err.to_string()))?;
    
        // Perform the multi-exponentiation
        config.install(|| {
            let bases = self.g1_ifft(polynomial.len()).unwrap();
            match G1Projective::msm(&bases, &polynomial.to_vec()) {
                Ok(res) => Ok(res.into_affine()),
                Err(err) => Err(KzgError::CommitError(err.to_string())),
            }
        })
    }

    /// 4844 compatible helper function
    pub fn blob_to_kzg_commitment(&self, blob: &Blob) -> Result<G1Affine, KzgError> {
        let polynomial = blob.to_polynomial().map_err(|err| KzgError::SerializationError(err.to_string()))?;
        let commitment = self.commit(&polynomial)?;
        Ok(commitment)
    }

    /// helper function to work with the library and the env of the kzg instance
    pub fn compute_kzg_proof_with_roots_of_unity(&self, polynomial: &Polynomial, index: u64) -> Result<G1Affine, KzgError>{
        self.compute_kzg_proof(polynomial, index, &self.expanded_roots_of_unity)
    }

    /// function to compute the kzg proof given the values.
    pub fn compute_kzg_proof(&self, polynomial: &Polynomial, index: u64, root_of_unities: &Vec<Fr>) -> Result<G1Affine, KzgError> {

        if !self.params.completed_setup {
            return Err(KzgError::GenericError("setup is not complete, run the data_setup functions".to_string()));
        }

        if polynomial.len() != root_of_unities.len() {
            return Err(KzgError::GenericError("inconsistent length between blob and root of unities".to_string()));
        }
    
        let eval_fr = polynomial.to_vec();
        let mut poly_shift: Vec<Fr> = Vec::with_capacity(eval_fr.len());
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
        
        let g1_lagrange = self.g1_ifft(polynomial.len())?;

        match G1Projective::msm(&g1_lagrange, &quotient_poly) {
            Ok(res) => Ok(G1Affine::from(res)),
            Err(err) => Err(KzgError::SerializationError(err.to_string())),
        }
    }

    /// refer to DA for more context
    fn compute_quotient_eval_on_domain(&self, z_fr: Fr, eval_fr: &Vec<Fr>, value_fr: Fr, roots_of_unities: &Vec<Fr>) -> Fr {

        let mut quotient = Fr::zero();
        let mut fi = Fr::zero();
        let mut numerator: Fr = Fr::zero();
        let mut denominator: Fr = Fr::zero(); 
        let mut temp: Fr = Fr::zero();
    
        for i in 0..roots_of_unities.len() {
            let omega_i = roots_of_unities[i];
            if omega_i == z_fr {
                continue
            }
            fi = eval_fr[i] - value_fr;
            numerator = fi.mul(omega_i);
            denominator = z_fr - omega_i;
            denominator = denominator * z_fr;
            temp = numerator.div(denominator);
            quotient = quotient + temp;
        }
        quotient
    }

    /// function to compute the inverse FFT
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

    pub fn verify_kzg_proof(&self, commitment: G1Affine, proof: G1Affine, value_fr: Fr, z_fr: Fr) -> bool {
        let g2_tau = if self.g2.len() > 28 { self.g2.get(1).unwrap().clone() } else { self.g2.get(0).unwrap().clone() };
        let value_g1 = (G1Affine::generator() * value_fr).into_affine();
        let commit_minus_value = (commitment - value_g1).into_affine();
        let z_g2 = (G2Affine::generator() * z_fr).into_affine();
        let x_minus_z = (g2_tau - z_g2).into_affine();
        Self::pairings_verify(commit_minus_value, G2Affine::generator(), proof, x_minus_z)
    }

    fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
        let neg_b1 = -b1;
        let p = [a1, neg_b1];
        let q = [a2, b2];
        let result = Bn254::multi_pairing(p, q);
        result.is_zero()
    }
    
}

#[test]
fn test_commit_errors(){

    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    let mut poly = vec![];
    for _ in 0..4000{
        poly.push(Fr::one());
    }

    let polynomial = Polynomial::new(&poly, 2).unwrap();
    let result = kzg.commit(&polynomial);
    assert_eq!(result, Err(KzgError::SerializationError("polynomial length is not correct".to_string())));
}

#[test]
fn test_kzg_setup_errors(){

    let kzg1 = Kzg::setup(
        "src/test-files/g1.point", 
        "",
        "",
        3000,
        3000
    );
    assert_eq!(kzg1, Err(KzgError::GenericError("both g2 point files are empty, need the proper file specified".to_string())));

    let mut kzg2 = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        2,
        2
    ).unwrap();

    let result = kzg2.data_setup_mins(4, 4);
    assert_eq!(result, Err(KzgError::SerializationError("the supplied encoding parameters are not valid with respect to the SRS.".to_string())));

    let kzg3 = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3001
    );
    assert_eq!(kzg3, Err(KzgError::GenericError("number of points to load is more than the srs order".to_string())));
}

#[test]
fn test_g2_power_of_2_readin(){

    use std::io::BufRead;
    use ark_bn254::{Fq, Fq2};
    use ark_bn254::G2Projective;
    use crate::helpers::is_on_curve_g2;

    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    assert_eq!(kzg.get_g2_points().len(), 28);

    let file = File::open("src/test-files/g2.powerOf2.string.txt").unwrap();
    let reader = BufReader::new(file);
    let kzg_g2_points = kzg.get_g2_points();

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
        assert_eq!(is_on_curve_g2(&G2Projective::from(point)), true);
        assert_eq!(point, kzg_g2_points[i]);
    }
}

#[test]
fn test_blob_to_kzg_commitment(){

    use crate::consts::GETTYSBURG_ADDRESS_BYTES;
    use ark_bn254::Fq;

    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    let blob = Blob::from_bytes_and_pad(GETTYSBURG_ADDRESS_BYTES);
    let fn_output = kzg.blob_to_kzg_commitment(&blob).unwrap();
    let commitment_from_da = G1Affine::new_unchecked(Fq::from_str("2961155957874067312593973807786254905069537311739090798303675273531563528369").unwrap(), Fq::from_str("159565752702690920280451512738307422982252330088949702406468210607852362941").unwrap());
    assert_eq!(commitment_from_da, fn_output);
}

#[test]
fn test_compute_kzg_proof_rand(){
    use rand::Rng;

    let mut kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    let mut rng = rand::thread_rng();

    (0..100).for_each(|_| {
        let blob_length = rand::thread_rng().gen_range(0..50000);
        let random_blob: Vec<u8> = (0..blob_length).map(|_| rng.gen_range(32..=126) as u8).collect();
        println!("generating blob of length is {}", blob_length);

        let input = Blob::from_bytes_and_pad(&random_blob);
        let input_poly = input.to_polynomial().unwrap();
        kzg.data_setup_custom(1, input.len().try_into().unwrap()).unwrap();

        let index = rand::thread_rng().gen_range(0..input_poly.get_length_of_padded_blob_as_fr_vector());
        let commitment = kzg.commit(&input_poly.clone()).unwrap();
        let proof = kzg.compute_kzg_proof_with_roots_of_unity(&input_poly, index.try_into().unwrap()).unwrap();
        let value_fr = input_poly.get_at_index(index).unwrap();
        let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
        let pairing_result = kzg.verify_kzg_proof(commitment, proof, value_fr.clone(), z_fr.clone());
        assert_eq!(pairing_result, true);

        // take random index, not the same index and check
        assert_eq!(kzg.verify_kzg_proof(commitment, proof, value_fr.clone(), kzg.get_nth_root_of_unity((index+1)%input_poly.get_length_of_padded_blob_as_fr_vector()).unwrap().clone()), false)
    })
}

#[test]
fn test_compute_kzg_proof(){
    use rand::Rng;
    use crate::consts::GETTYSBURG_ADDRESS_BYTES;

    let mut kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    let input = Blob::from_bytes_and_pad(GETTYSBURG_ADDRESS_BYTES);
    let input_poly = input.to_polynomial().unwrap();
    
    for index in 0..input_poly.len()-1 {
        // let index = rand::thread_rng().gen_range(0..input_poly.len());
        kzg.data_setup_custom(4, input.len().try_into().unwrap()).unwrap();
        let mut rand_index = rand::thread_rng().gen_range(0..kzg.expanded_roots_of_unity.len());
        loop {
            if index == rand_index{
                rand_index = rand::thread_rng().gen_range(0..kzg.expanded_roots_of_unity.len());
            } else {
                break;
            }
        }
        let commitment = kzg.commit(&input_poly.clone()).unwrap();
        let proof = kzg.compute_kzg_proof_with_roots_of_unity(&input_poly, index.try_into().unwrap()).unwrap();
        let value_fr = input_poly.get_at_index(index).unwrap();
        let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
        let pairing_result = kzg.verify_kzg_proof(commitment, proof, value_fr.clone(), z_fr.clone());
        assert_eq!(pairing_result, true);
        assert_eq!(kzg.verify_kzg_proof(commitment, proof, value_fr.clone(), kzg.get_nth_root_of_unity(rand_index).unwrap().clone()), false)
    }
}

#[test]
fn test_compute_kzg_proof_output_from_da(){

    use ark_bn254::Fq;
    use std::io::BufRead;
    use crate::helpers::str_vec_to_fr_vec;

    let mut kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    let padded_input_fr_elements_raw: Vec<&str> = vec!["124448554745810004944228143885327110275920855486363883336842102793103679599",
    "207508779162842735480548510602597324319082308236775252882533101718680401000",
    "186313515821661738828935773908502628014528503825682615305243860329822383982",
    "175617779057046250607386263835676382877324402797999043923860409846702634085",
    "176908701417764592253495595071883691502347870932091779502876015283829219437",
    "179211618621408803906861370832182601073979563282871012483254698763530297714",
    "178675144007207845453916698249955375488211072406922195772122332854753522220",
    "57342443762551981711519063259175130140327164323119403383994481075796320367",
    "201644048016840536514201229857164309383055459782299704545143570201060467744",
    "203954379585240811567952376700119386006707415102080467720847989508363595296",
    "154413643997390308462567944070940706665567667980552003158571865495684605545",
    "179199641558557109502508265885652506531258925160729980997532492238197956724",
    "196343586746013098463529914279508021337660652896452822254975184458999686761",
    "179199642789798378766954615916637942576983085081216829572950655633119846502",
    "196907698251416180188206806476118527217227835524517227212890708462578723945",
    "209188135065833850053292603115533125810196283005470024563599194921554962806",
    "178769904328431539945589819940519599680679301078162293895893458713281916516",
    "57315186833570416806491652511576227840442154124102492634747207086848439086",
    "56997787879934999878051099065093180857197870434076438449626313283955024238",
    "195122401735223296672399273363582347617293258088862337245338589498286891890",
    "172187514667817006797016147089450681237387563021330251172649930984059510887",
    "202189825168553442339042346633289285996072565593325159962613855263274328430",
    "176908269032208360895799213956941641962632779042122566173195460097279025526",
    "178675090195535348079425008943654955291233237035453597549103224288057848352",
    "198655969672698814635678440561840379961683740854293905470589343214280253524",
    "184450046414280497382771444868504084637083498078940578643710020946530103840",
    "191588553295206552672446505441400871035933706577055546498217912677470201132",
    "57218643758213157866498392310103913473502406903700483504908744830152351860",
    "184452436682824846772926756876560010960143362270644037512475344570444965152",
    "191547358739393032699638562397393592082434780603568324919651475504456033636",
    "57259622694790292569095949658502840145070150663520147255610723074247260008",
    "186205021942396728157785116391788484694464475366678317619183801399752597620",
    "184562702865503477544474983818908595115462442551772541350836446300829130857",
    "203411352029711233470829194006802304117968683302211457541840894875429856361",
    "175590466840243348133688030338994426426205333357416292443952411731112324713",
    "195064930079953233979471617089854997241218347662186974737524940518540404000",
    "184521165912303293767845148683223315441296689539961647976806104757436769312",
    "177384975870124439001759657886337745043336278262654552223156680275429714275",
    "183976088968084624324785031346616746677350639582380167858351783587217173536",
    "193286033715924828384520581373366850088713852669139898226901243602529493096",
    "179241078993710153255069385145856351420066197647806384293982409561076998244",
    "179123722350391539550068374677188552845397193776842784699159030602666174830",
    "400194862503576342918173310331854693478403117005444701857659884415883371564",
    "57335620997137264681921969532598204329752055368260135437058948058890528101",
    "177453743603580340760143914089201876349834419692598030679062113821757040741",
    "57314836354274911098352906734004791591005704793885798411715484369110198373",
    "57314836354274911098359242714508940270452740705366016780345068008093216032",
    "205674767500671097980546524606502860210905462284178340164141948154901692416",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",];

    let roots_of_unities_raw: Vec<&str> = vec!["1",
    "9088801421649573101014283686030284801466796108869023335878462724291607593530",
    "4419234939496763621076330863786513495701855246241724391626358375488475697872",
    "10685529837057339195284478417809549783849082573663680590416001084635768485990",
    "14940766826517323942636479241147756311199852622225275649687664389641784935947",
    "1267043552012899406804021742775506022406234352662757946107381425245432910045",
    "8353089677377103612376907029239831201621163137110616679113215703556701300027",
    "2441140650056668192559128307232955355464329046106249160729745552573818873507",
    "19540430494807482326159819597004422086093766032135589407132600596362845576832",
    "7638532900060318363441136974856672991261030096006837046428044865340598824945",
    "21593175090660679728966189540082956087710442206243643852421469785983375007422",
    "1938211124727238839182731185938102527032692606309510708934917132548164554613",
    "7453743110195651009871841175551411207906567694170420694440975759997908783171",
    "18272962628503604941710624384101461447671738503426463821117705461905178580283",
    "398060900184764123111996659293386330445164342166284510961681463198684035472",
    "2283482550034800628111070180390673268453179470922704452226293886212258993410",
    "21888242871839275217838484774961031246007050428528088939761107053157389710902",
    "20789857765414837569378861847135321604271811148012132377696013003867187003108",
    "15480425210935858833842661136375613442295926160997485829640439761218028937032",
    "18528082246067560296180016805056907225377865863446968862116791721065802134110",
    "15634706786522089014999940912207647497621112715300598509090847765194894752723",
    "10638720336917081690638245448031473930540403837643333986712680212230728663233",
    "9222527969605388450625148037496647087331675164191659244434925070698893435503",
    "1517838647035931137528481530777492051607999820652391703425676009405898040794",
    "13274704216607947843011480449124596415239537050559949017414504948711435969894",
    "8682033663657132234291766569813810281833069931144526641976190784581352362959",
    "10550721784764313104495045260998680866741519845912303749987955721122349694799",
    "10234189842755395200346026196803257362626336236511351459013434557394886321135",
    "20580681596408674675161806693190042586237586932987042748222592033583012763427",
    "21262384822466439274137541430102393376441243110026393623692977826997277779276",
    "4183653929190742691274098379026487729755080010366834215927449156672627370084",
    "4658854783519236281304787251426829785380272013053939496434657852755686889074",
    "-1",
    "12799441450189702121232122059226990287081568291547011007819741462284200902087",
    "17469007932342511601170074881470761592846509154174309952071845811087332797745",
    "11202713034781936026961927327447725304699281826752353753282203101940040009627",
    "6947476045321951279609926504109518777348511778190758694010539796934023559670",
    "20621199319826375815442384002481769066142130047753276397590822761330375585572",
    "13535153194462171609869498716017443886927201263305417664584988483019107195590",
    "19447102221782607029687277438024319733084035354309785182968458634001989622110",
    "2347812377031792896086586148252853002454598368280444936565603590212962918785",
    "14249709971778956858805268770400602097287334304409197297270159321235209670672",
    "295067781178595493280216205174319000837922194172390491276734400592433488195",
    "19950031747112036383063674559319172561515671794106523634763287054027643941004",
    "14434499761643624212374564569705863880641796706245613649257228426577899712446",
    "3615280243335670280535781361155813640876625896989570522580498724670629915334",
    "21490181971654511099134409085963888758103200058249749832736522723377124460145",
    "19604760321804474594135335564866601820095184929493329891471910300363549502207",
    "4407920970296243842541313971887945403937097133418418784715",
    "1098385106424437652867543898121953484276553252403901966002191182708621492509",
    "6407817660903416388403744608881661646252438239418548514057764425357779558585",
    "3360160625771714926066388940200367863170498536969065481581412465510006361507",
    "6253536085317186207246464833049627590927251685115435834607356421380913742894",
    "11249522534922193531608160297225801158007960562772700356985523974345079832384",
    "12665714902233886771621257707760628001216689236224375099263279115876915060114",
    "20370404224803344084717924214479783036940364579763642640272528177169910454823",
    "8613538655231327379234925296132678673308827349856085326283699237864372525723",
    "13206209208182142987954639175443464806715294469271507701722013401994456132658",
    "11337521087074962117751360484258594221806844554503730593710248465453458800818",
    "11654053029083880021900379548454017725922028163904682884684769629180922174482",
    "1307561275430600547084599052067232502310777467428991595475612152992795732190",
    "625858049372835948108864315154881712107121290389640720005226359578530716341",
    "17704588942648532530972307366230787358793284390049200127770755029903181125533",
    "17229388088320038940941618493830445303168092387362094847263546333820121606543"];

    let roots_of_unities: Vec<Fr> = str_vec_to_fr_vec(roots_of_unities_raw).unwrap();
    let padded_input_fr_elements: Vec<Fr> = str_vec_to_fr_vec(padded_input_fr_elements_raw).unwrap();



    let file2 = File::open("src/test-files/kzg.proof.eq.input").unwrap();
    let reader2 = BufReader::new(file2);

    for line in reader2.lines() {
        let line = line.unwrap();
        let trimmed_line = line.trim_end(); // Trim whitespace from the end
        let the_strings_str: Vec<&str> = trimmed_line.split(',').collect(); // Split the line on commas
        let index = u64::from_str(the_strings_str[0]).unwrap();
        let hard_coded_x = Fq::from_str(the_strings_str[1]).expect("should be fine");
        let hard_coded_y = Fq::from_str(the_strings_str[2]).expect("should be fine");
        let gnark_proof = G1Affine::new(hard_coded_x, hard_coded_y);
        let poly = Polynomial::new(&padded_input_fr_elements, 30).unwrap();
        kzg.data_setup_custom(4, poly.len().try_into().unwrap()).unwrap();
        let result = kzg.compute_kzg_proof(&poly, index, &roots_of_unities).unwrap();
        assert_eq!(gnark_proof, result)
    }
}

#[test]
fn test_g1_ifft(){
    use std::io::BufRead;
    use ark_bn254::Fq;

    let file = File::open("src/test-files/lagrangeG1SRS.txt").unwrap();
    let reader = BufReader::new(file);
    
    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
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
    use ark_bn254::Fq;
    
    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
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
    use ark_bn254::{Fq, Fq2};

    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
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

#[test]
fn test_compute_quotient_eval_on_domain(){
    
    use crate::helpers;
    let kzg = Kzg::setup(
        "src/test-files/g1.point", 
        "src/test-files/g2.point",
        "src/test-files/g2.point.powerOf2",
        3000,
        3000
    ).unwrap();

    let z_fr = Fr::from_str("18272962628503604941710624384101461447671738503426463821117705461905178580283").expect("yes");
    let value_fr = Fr::from_str("179199642789798378766954615916637942576983085081216829572950655633119846502").expect("yes");
    let eval_raw: Vec<&str> = vec!["124448554745810004944228143885327110275920855486363883336842102793103679599",
    "207508779162842735480548510602597324319082308236775252882533101718680401000",
    "186313515821661738828935773908502628014528503825682615305243860329822383982",
    "175617779057046250607386263835676382877324402797999043923860409846702634085",
    "176908701417764592253495595071883691502347870932091779502876015283829219437",
    "179211618621408803906861370832182601073979563282871012483254698763530297714",
    "178675144007207845453916698249955375488211072406922195772122332854753522220",
    "57342443762551981711519063259175130140327164323119403383994481075796320367",
    "201644048016840536514201229857164309383055459782299704545143570201060467744",
    "203954379585240811567952376700119386006707415102080467720847989508363595296",
    "154413643997390308462567944070940706665567667980552003158571865495684605545",
    "179199641558557109502508265885652506531258925160729980997532492238197956724",
    "196343586746013098463529914279508021337660652896452822254975184458999686761",
    "179199642789798378766954615916637942576983085081216829572950655633119846502",
    "196907698251416180188206806476118527217227835524517227212890708462578723945",
    "209188135065833850053292603115533125810196283005470024563599194921554962806",
    "178769904328431539945589819940519599680679301078162293895893458713281916516",
    "57315186833570416806491652511576227840442154124102492634747207086848439086",
    "56997787879934999878051099065093180857197870434076438449626313283955024238",
    "195122401735223296672399273363582347617293258088862337245338589498286891890",
    "172187514667817006797016147089450681237387563021330251172649930984059510887",
    "202189825168553442339042346633289285996072565593325159962613855263274328430",
    "176908269032208360895799213956941641962632779042122566173195460097279025526",
    "178675090195535348079425008943654955291233237035453597549103224288057848352",
    "198655969672698814635678440561840379961683740854293905470589343214280253524",
    "184450046414280497382771444868504084637083498078940578643710020946530103840",
    "191588553295206552672446505441400871035933706577055546498217912677470201132",
    "57218643758213157866498392310103913473502406903700483504908744830152351860",
    "184452436682824846772926756876560010960143362270644037512475344570444965152",
    "191547358739393032699638562397393592082434780603568324919651475504456033636",
    "57259622694790292569095949658502840145070150663520147255610723074247260008",
    "186205021942396728157785116391788484694464475366678317619183801399752597620",
    "184562702865503477544474983818908595115462442551772541350836446300829130857",
    "203411352029711233470829194006802304117968683302211457541840894875429856361",
    "175590466840243348133688030338994426426205333357416292443952411731112324713",
    "195064930079953233979471617089854997241218347662186974737524940518540404000",
    "184521165912303293767845148683223315441296689539961647976806104757436769312",
    "177384975870124439001759657886337745043336278262654552223156680275429714275",
    "183976088968084624324785031346616746677350639582380167858351783587217173536",
    "193286033715924828384520581373366850088713852669139898226901243602529493096",
    "179241078993710153255069385145856351420066197647806384293982409561076998244",
    "179123722350391539550068374677188552845397193776842784699159030602666174830",
    "400194862503576342918173310331854693478403117005444701857659884415883371564",
    "57335620997137264681921969532598204329752055368260135437058948058890528101",
    "177453743603580340760143914089201876349834419692598030679062113821757040741",
    "57314836354274911098352906734004791591005704793885798411715484369110198373",
    "57314836354274911098359242714508940270452740705366016780345068008093216032",
    "205674767500671097980546524606502860210905462284178340164141948154901692416",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0",
    "0"];

    let roots_of_unities_raw: Vec<&str> = vec!["1",
    "9088801421649573101014283686030284801466796108869023335878462724291607593530",
    "4419234939496763621076330863786513495701855246241724391626358375488475697872",
    "10685529837057339195284478417809549783849082573663680590416001084635768485990",
    "14940766826517323942636479241147756311199852622225275649687664389641784935947",
    "1267043552012899406804021742775506022406234352662757946107381425245432910045",
    "8353089677377103612376907029239831201621163137110616679113215703556701300027",
    "2441140650056668192559128307232955355464329046106249160729745552573818873507",
    "19540430494807482326159819597004422086093766032135589407132600596362845576832",
    "7638532900060318363441136974856672991261030096006837046428044865340598824945",
    "21593175090660679728966189540082956087710442206243643852421469785983375007422",
    "1938211124727238839182731185938102527032692606309510708934917132548164554613",
    "7453743110195651009871841175551411207906567694170420694440975759997908783171",
    "18272962628503604941710624384101461447671738503426463821117705461905178580283",
    "398060900184764123111996659293386330445164342166284510961681463198684035472",
    "2283482550034800628111070180390673268453179470922704452226293886212258993410",
    "21888242871839275217838484774961031246007050428528088939761107053157389710902",
    "20789857765414837569378861847135321604271811148012132377696013003867187003108",
    "15480425210935858833842661136375613442295926160997485829640439761218028937032",
    "18528082246067560296180016805056907225377865863446968862116791721065802134110",
    "15634706786522089014999940912207647497621112715300598509090847765194894752723",
    "10638720336917081690638245448031473930540403837643333986712680212230728663233",
    "9222527969605388450625148037496647087331675164191659244434925070698893435503",
    "1517838647035931137528481530777492051607999820652391703425676009405898040794",
    "13274704216607947843011480449124596415239537050559949017414504948711435969894",
    "8682033663657132234291766569813810281833069931144526641976190784581352362959",
    "10550721784764313104495045260998680866741519845912303749987955721122349694799",
    "10234189842755395200346026196803257362626336236511351459013434557394886321135",
    "20580681596408674675161806693190042586237586932987042748222592033583012763427",
    "21262384822466439274137541430102393376441243110026393623692977826997277779276",
    "4183653929190742691274098379026487729755080010366834215927449156672627370084",
    "4658854783519236281304787251426829785380272013053939496434657852755686889074",
    "-1",
    "12799441450189702121232122059226990287081568291547011007819741462284200902087",
    "17469007932342511601170074881470761592846509154174309952071845811087332797745",
    "11202713034781936026961927327447725304699281826752353753282203101940040009627",
    "6947476045321951279609926504109518777348511778190758694010539796934023559670",
    "20621199319826375815442384002481769066142130047753276397590822761330375585572",
    "13535153194462171609869498716017443886927201263305417664584988483019107195590",
    "19447102221782607029687277438024319733084035354309785182968458634001989622110",
    "2347812377031792896086586148252853002454598368280444936565603590212962918785",
    "14249709971778956858805268770400602097287334304409197297270159321235209670672",
    "295067781178595493280216205174319000837922194172390491276734400592433488195",
    "19950031747112036383063674559319172561515671794106523634763287054027643941004",
    "14434499761643624212374564569705863880641796706245613649257228426577899712446",
    "3615280243335670280535781361155813640876625896989570522580498724670629915334",
    "21490181971654511099134409085963888758103200058249749832736522723377124460145",
    "19604760321804474594135335564866601820095184929493329891471910300363549502207",
    "4407920970296243842541313971887945403937097133418418784715",
    "1098385106424437652867543898121953484276553252403901966002191182708621492509",
    "6407817660903416388403744608881661646252438239418548514057764425357779558585",
    "3360160625771714926066388940200367863170498536969065481581412465510006361507",
    "6253536085317186207246464833049627590927251685115435834607356421380913742894",
    "11249522534922193531608160297225801158007960562772700356985523974345079832384",
    "12665714902233886771621257707760628001216689236224375099263279115876915060114",
    "20370404224803344084717924214479783036940364579763642640272528177169910454823",
    "8613538655231327379234925296132678673308827349856085326283699237864372525723",
    "13206209208182142987954639175443464806715294469271507701722013401994456132658",
    "11337521087074962117751360484258594221806844554503730593710248465453458800818",
    "11654053029083880021900379548454017725922028163904682884684769629180922174482",
    "1307561275430600547084599052067232502310777467428991595475612152992795732190",
    "625858049372835948108864315154881712107121290389640720005226359578530716341",
    "17704588942648532530972307366230787358793284390049200127770755029903181125533",
    "17229388088320038940941618493830445303168092387362094847263546333820121606543"];

    let mut eval_fr: Vec<Fr> = vec![];
    let roots_of_unities: Vec<Fr> = helpers::str_vec_to_fr_vec(roots_of_unities_raw).unwrap();
    for i in 0..eval_raw.len() {
        eval_fr.push(Fr::from_str(eval_raw[i]).expect("yes"));
    }

    let result = kzg.compute_quotient_eval_on_domain(z_fr, &eval_fr, value_fr, &roots_of_unities);
    let confirmed_result = Fr::from_str("20008798420615294489302706738008175134837093401197634135729610787152508035605").expect("yes");

    assert_eq!(confirmed_result, result);

}
