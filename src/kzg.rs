use crate::{
    blob::Blob,
    consts::{BYTES_PER_FIELD_ELEMENT, SIZE_OF_G1_AFFINE_COMPRESSED},
    errors::{BlobError, KzgError},
    helpers::{self, check_directory, is_on_curve_g2},
    polynomial::{Polynomial, PolynomialFormat},
    traits::ReadPointFromBytes,
};

use crate::consts::{
    Endianness, FIAT_SHAMIR_PROTOCOL_DOMAIN, FIELD_ELEMENTS_PER_BLOB, KZG_ENDIANNESS,
    RANDOM_CHALLENGE_KZG_BATCH_DOMAIN,
};
use crate::helpers::is_on_curve_g1;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalSerialize;
use ark_serialize::{Read, Write};
use ark_std::{ops::Div, str::FromStr, One, Zero};
use crossbeam_channel::{bounded, Sender};
use num_traits::ToPrimitive;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, BufReader},
};

#[derive(Debug, PartialEq, Clone)]
pub struct Kzg {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    params: Params,
    srs_order: u64,
    expanded_roots_of_unity: Vec<Fr>,
    cache_dir: String,
}

#[derive(Debug, PartialEq, Clone)]
struct Params {
    chunk_length: u64,
    num_chunks: u64,
    max_fft_width: u64,
    completed_setup: bool,
}

impl Kzg {
    pub fn setup(
        path_to_g1_points: &str,
        path_to_g2_points: &str,
        g2_power_of2_path: &str,
        srs_order: u32,
        srs_points_to_load: u32,
        cache_dir: String,
    ) -> Result<Self, KzgError> {
        if srs_points_to_load > srs_order {
            return Err(KzgError::GenericError(
                "number of points to load is more than the srs order".to_string(),
            ));
        }

        if !cache_dir.is_empty() {
            if let Err(err) = check_directory(&cache_dir) {
                return Err(KzgError::GenericError(err));
            }
        }

        let g1_points =
            Self::parallel_read_g1_points(path_to_g1_points.to_owned(), srs_points_to_load, false)
                .map_err(|e| KzgError::SerializationError(e.to_string()))?;

        let g2_points: Vec<G2Affine> =
            match (path_to_g2_points.is_empty(), g2_power_of2_path.is_empty()) {
                (false, _) => Self::parallel_read_g2_points(
                    path_to_g2_points.to_owned(),
                    srs_points_to_load,
                    false,
                )
                .map_err(|e| KzgError::SerializationError(e.to_string()))?,
                (_, false) => Self::read_g2_point_on_power_of_2(g2_power_of2_path)?,
                (true, true) => {
                    return Err(KzgError::GenericError(
                        "both g2 point files are empty, need the proper file specified".to_string(),
                    ))
                },
            };

        Ok(Self {
            g1: g1_points,
            g2: g2_points,
            params: Params {
                chunk_length: 0,
                num_chunks: 0,
                max_fft_width: 0,
                completed_setup: false,
            },
            srs_order: srs_order.into(),
            expanded_roots_of_unity: vec![],
            cache_dir,
        })
    }

    pub fn read_g2_point_on_power_of_2(g2_power_of2_path: &str) -> Result<Vec<G2Affine>, KzgError> {
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
            chunks.push(G2Affine::read_point_from_bytes_be(&buffer[..bytes_read]).unwrap());
        }
        Ok(chunks)
    }

    fn calculate_roots_of_unity_non_assign(
        length_of_data_after_padding: u64,
        srs_order: u64,
    ) -> Result<(Params, Vec<Fr>), KzgError> {
        let mut params = Params {
            num_chunks: 0_u64,
            chunk_length: 0_u64,
            max_fft_width: 0_u64,
            completed_setup: false,
        };
        let log2_of_evals = length_of_data_after_padding
            .div_ceil(32)
            .next_power_of_two()
            .to_f64()
            .unwrap()
            .log2()
            .to_u8()
            .unwrap();
        params.max_fft_width = 1_u64 << log2_of_evals;

        if length_of_data_after_padding
            .div_ceil(BYTES_PER_FIELD_ELEMENT as u64)
            .next_power_of_two()
            >= srs_order
        {
            return Err(KzgError::SerializationError(
                "the supplied encoding parameters are not valid with respect to the SRS."
                    .to_string(),
            ));
        }

        let primitive_roots_of_unity = Self::get_primitive_roots_of_unity();
        let found_root_of_unity = primitive_roots_of_unity
            .get(log2_of_evals as usize)
            .unwrap();
        let mut expanded_roots_of_unity = Self::expand_root_of_unity(found_root_of_unity);
        expanded_roots_of_unity.truncate(expanded_roots_of_unity.len() - 1);

        params.completed_setup = true;

        Ok((params, expanded_roots_of_unity))
    }

    /// data_setup_custom is a helper function
    pub fn data_setup_custom(
        &mut self,
        num_of_nodes: u64,
        padded_input_data_size: u64,
    ) -> Result<(), KzgError> {
        let floor = u64::try_from(BYTES_PER_FIELD_ELEMENT)
            .map_err(|e| KzgError::SerializationError(e.to_string()))?;
        let len_of_data_in_elements = padded_input_data_size.div_ceil(floor);
        let min_num_chunks = len_of_data_in_elements.div_ceil(num_of_nodes);
        self.data_setup_mins(min_num_chunks, num_of_nodes)
    }

    /// data_setup_mins sets up the environment per the blob data
    pub fn data_setup_mins(
        &mut self,
        min_chunk_length: u64,
        min_num_chunks: u64,
    ) -> Result<(), KzgError> {
        let mut params = Params {
            num_chunks: min_num_chunks.next_power_of_two(),
            chunk_length: min_chunk_length.next_power_of_two(),
            max_fft_width: 0_u64,
            completed_setup: false,
        };

        let number_of_evaluations = params.chunk_length * params.num_chunks;
        let mut log2_of_evals = number_of_evaluations
            .to_f64()
            .unwrap()
            .log2()
            .to_u8()
            .unwrap();
        params.max_fft_width = 1_u64 << log2_of_evals;

        if params.chunk_length == 1 {
            log2_of_evals = (2 * params.num_chunks)
                .to_f64()
                .unwrap()
                .log2()
                .to_u8()
                .unwrap();
        }

        if params.chunk_length * params.num_chunks >= self.srs_order {
            return Err(KzgError::SerializationError(
                "the supplied encoding parameters are not valid with respect to the SRS."
                    .to_string(),
            ));
        }

        let primitive_roots_of_unity = Self::get_primitive_roots_of_unity();
        let found_root_of_unity = primitive_roots_of_unity
            .get(log2_of_evals.to_usize().unwrap())
            .unwrap();
        let mut expanded_roots_of_unity = Self::expand_root_of_unity(found_root_of_unity);
        expanded_roots_of_unity.truncate(expanded_roots_of_unity.len() - 1);

        params.completed_setup = true;
        self.params = params;
        self.expanded_roots_of_unity = expanded_roots_of_unity;

        Ok(())
    }

    pub fn calculate_roots_of_unity(
        &mut self,
        length_of_data_after_padding: u64,
    ) -> Result<(), KzgError> {
        let (params, roots_of_unity) = Self::calculate_roots_of_unity_non_assign(
            length_of_data_after_padding,
            self.srs_order,
        )?;
        self.params = params;
        self.params.completed_setup = true;
        self.expanded_roots_of_unity = roots_of_unity;

        Ok(())
    }

    /// helper function to get the
    pub fn get_nth_root_of_unity(&self, i: usize) -> Option<&Fr> {
        self.expanded_roots_of_unity.get(i)
    }

    /// function to expand the roots based on the configuration
    fn expand_root_of_unity(root_of_unity: &Fr) -> Vec<Fr> {
        let mut roots = vec![Fr::one()]; // Initialize with 1
        roots.push(*root_of_unity); // Add the root of unity

        let mut i = 1;
        while !roots[i].is_one() {
            // Continue until the element cycles back to one
            let this = &roots[i];
            i += 1;
            roots.push(this * root_of_unity); // Push the next power of the root
                                              // of unity
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
            "19103219067921713944291392827692070036145651957329286315305642004821462161904",
        ];
        data.iter()
            .map(|each| Fr::from_str(each).unwrap())
            .collect()
    }

    /// helper function to get g1 points
    pub fn get_g1_points(&self) -> Vec<G1Affine> {
        self.g1.to_vec()
    }

    /// read files in chunks with specified length
    /// TODO: chunks seems misleading here, since we read one field element at a time.
    fn read_file_chunks(
        file_path: &str,
        sender: Sender<(Vec<u8>, usize, bool)>,
        point_size: usize,
        num_points: u32,
        is_native: bool,
    ) -> io::Result<()> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut position = 0;
        let mut buffer = vec![0u8; point_size];

        let mut i = 0;
        // We are making one syscall per field element, which is super inefficient.
        // FIXME: Read the entire file (or large segments) into memory and then split it into field elements.
        // Entire G1 file might be ~8GiB, so might not fit in RAM.
        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            sender
                .send((buffer[..bytes_read].to_vec(), position, is_native))
                .unwrap();
            position += bytes_read;
            buffer.resize(point_size, 0); // Ensure the buffer is always the correct size
            i += 1;
            if num_points == i {
                break;
            }
        }
        Ok(())
    }

    /// read G2 points in parallel
    pub fn parallel_read_g2_points(
        file_path: String,
        srs_points_to_load: u32,
        is_native: bool,
    ) -> Result<Vec<G2Affine>, KzgError> {
        let (sender, receiver) = bounded::<(Vec<u8>, usize, bool)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 64, srs_points_to_load, is_native)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            },
        );

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers)
            .map(|_| {
                let receiver = receiver.clone();
                std::thread::spawn(move || helpers::process_chunks::<G2Affine>(receiver))
            })
            .collect();

        // Wait for the reader thread to finish
        match reader_thread.join() {
            Ok(result) => match result {
                Ok(_) => {},
                Err(e) => return Err(KzgError::GenericError(e.to_string())),
            },
            Err(_) => return Err(KzgError::GenericError("Thread panicked".to_string())),
        }

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

    /// read G1 points in parallel, by creating one reader thread, which reads bytes from the file,
    /// and fans them out to worker threads (one per cpu) which parse the bytes into G1Affine points.
    /// The worker threads then fan in the parsed points to the main thread, which sorts them by
    /// their original position in the file to maintain order.
    ///
    /// # Arguments
    /// * `file_path` - The path to the file containing the G1 points
    /// * `srs_points_to_load` - The number of points to load from the file
    /// * `is_native` - Whether the points are in native arkworks format or not
    ///
    /// # Returns
    /// * `Ok(Vec<G1Affine>)` - The G1 points read from the file
    /// * `Err(KzgError)` - An error occurred while reading the file
    pub fn parallel_read_g1_points_native(
        file_path: String,
        srs_points_to_load: u32,
        is_native: bool,
    ) -> Result<Vec<G1Affine>, KzgError> {
        // Channel contains (bytes, position, is_native) tuples. The position is used to reorder the points after processing them.
        let (sender, receiver) = bounded::<(Vec<u8>, usize, bool)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 32, srs_points_to_load, is_native)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            },
        );

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers)
            .map(|_| {
                let receiver = receiver.clone();
                std::thread::spawn(move || helpers::process_chunks::<G1Affine>(receiver))
            })
            .collect();

        // Wait for the reader thread to finish
        match reader_thread.join() {
            Ok(result) => match result {
                Ok(_) => {},
                Err(e) => return Err(KzgError::GenericError(e.to_string())),
            },
            Err(_) => return Err(KzgError::GenericError("Thread panicked".to_string())),
        }

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
    pub fn parallel_read_g1_points(
        file_path: String,
        srs_points_to_load: u32,
        is_native: bool,
    ) -> Result<Vec<G1Affine>, KzgError> {
        let (sender, receiver) = bounded::<(Vec<u8>, usize, bool)>(1000);

        // Spawning the reader thread
        let reader_handle = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 32, srs_points_to_load, is_native)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            },
        );

        let num_workers = num_cpus::get();

        let worker_handles: Vec<_> = (0..num_workers)
            .map(|_| {
                let receiver = receiver.clone();
                std::thread::spawn(move || helpers::process_chunks::<G1Affine>(receiver))
            })
            .collect();

        // Wait for the reader thread to finish
        match reader_handle.join() {
            Ok(result) => match result {
                Ok(_) => {},
                Err(e) => return Err(KzgError::GenericError(e.to_string())),
            },
            Err(_) => return Err(KzgError::GenericError("Thread panicked".to_string())),
        }

        // Collect and sort results
        let mut all_points = Vec::new();
        for handle in worker_handles {
            let points = handle.join().expect("Worker thread panicked");
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

    pub fn commit_with_cache(
        polynomial: &Polynomial,
        cache_dir: &str,
    ) -> Result<G1Affine, KzgError> {
        let poly_len = polynomial.len();

        let bases = Self::read_from_cache_if_exists(poly_len, cache_dir);
        if bases.is_empty() {
            return Err(KzgError::CommitError(
                "unable to commit using cache.".to_string(),
            ));
        }

        match G1Projective::msm(&bases, &polynomial.to_vec()) {
            Ok(res) => Ok(res.into_affine()),
            Err(err) => Err(KzgError::CommitError(err.to_string())),
        }
    }

    /// commit the actual polynomial with the values setup
    pub fn commit(&self, polynomial: &Polynomial) -> Result<G1Affine, KzgError> {
        if polynomial.len() > self.g1.len() {
            return Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string(),
            ));
        }

        let bases = match polynomial.get_form() {
            PolynomialFormat::InEvaluationForm => {
                // If the polynomial is in evaluation form, use the original g1 points
                self.g1[..polynomial.len()].to_vec()
            },
            PolynomialFormat::InCoefficientForm => {
                // If the polynomial is in coefficient form, use inverse FFT
                self.g1_ifft(polynomial.len())?
            },
        };

        match G1Projective::msm(&bases, &polynomial.to_vec()) {
            Ok(res) => Ok(res.into_affine()),
            Err(err) => Err(KzgError::CommitError(err.to_string())),
        }
    }

    pub fn blob_to_kzg_commitment(
        &self,
        blob: &Blob,
        form: PolynomialFormat,
    ) -> Result<G1Affine, KzgError> {
        let polynomial = blob
            .to_polynomial(form)
            .map_err(|err| KzgError::SerializationError(err.to_string()))?;
        let commitment = self.commit(&polynomial)?;
        Ok(commitment)
    }

    /// helper function to work with the library and the env of the kzg instance
    pub fn compute_kzg_proof_with_roots_of_unity(
        &self,
        polynomial: &Polynomial,
        index: u64,
    ) -> Result<G1Affine, KzgError> {
        self.compute_kzg_proof_eigenda(polynomial, index)
    }
    

    // Need a better name for this. This is used to keep in line with 4844 naming but 
    // this is a bit misleading since compute_kzg_proof doesn't use it and our current implementation is 
    // DA specific and has additional params. Also this needs to coalese into the compute_kzg_proof because it's
    // largely a copy paste of compute_kzg_proof but current compute_kzg_proof has some DA uniqueness to it.
    pub fn compute_kzg_proof_impl(
        &self,
        polynomial: &Polynomial,
        z_fr: &Fr,
    ) -> Result<G1Affine, KzgError> {
        if !self.params.completed_setup {
            return Err(KzgError::GenericError(
                "setup is not complete, run the data_setup functions".to_string(),
            ));
        }

        if polynomial.len() != self.expanded_roots_of_unity.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }

        let eval_fr = polynomial.to_vec();
        let mut poly_shift: Vec<Fr> = Vec::with_capacity(eval_fr.len());

        let y_fr = Self::evaluate_polynomial_in_evaluation_form(polynomial, &z_fr, self.srs_order)?;

        for fr in &eval_fr {
            poly_shift.push(*fr - y_fr);
        }

        let mut denom_poly = Vec::<Fr>::with_capacity(self.expanded_roots_of_unity.len());
        for root_of_unity in self.expanded_roots_of_unity.iter().take(eval_fr.len()) {
            denom_poly.push(*root_of_unity - z_fr);
        }

        let mut quotient_poly = Vec::<Fr>::with_capacity(self.expanded_roots_of_unity.len());

        for i in 0..self.expanded_roots_of_unity.len() {
            if denom_poly[i].is_zero() {
                quotient_poly.push(self.compute_quotient_eval_on_domain(
                    z_fr,
                    &eval_fr,
                    &y_fr,
                    &self.expanded_roots_of_unity,
                ));
            } else {
                quotient_poly.push(poly_shift[i].div(denom_poly[i]));
            }
        }

        let bases = match polynomial.get_form() {
            PolynomialFormat::InEvaluationForm => {
                // If the polynomial is in evaluation form, use the original g1 points
                self.g1[..polynomial.len()].to_vec()
            },
            PolynomialFormat::InCoefficientForm => {
                // If the polynomial is in coefficient form, use inverse FFT
                self.g1_ifft(polynomial.len())?
            },
        };

        match G1Projective::msm(&bases, &quotient_poly) {
            Ok(res) => Ok(G1Affine::from(res)),
            Err(err) => Err(KzgError::SerializationError(err.to_string())),
        }
    }


    pub fn compute_kzg_proof_eigenda(
        &self,
        polynomial: &Polynomial,
        index: u64,
    ) -> Result<G1Affine, KzgError> {

        let usized_index = if let Some(x) = index.to_usize() {
            x
        } else {
            return Err(KzgError::SerializationError(
                "index couldn't be converted to usize".to_string(),
            ));
        };

        let z_fr = self.expanded_roots_of_unity[usized_index];
        self.compute_kzg_proof(polynomial, &z_fr)
    }    
    
    /// Compute KZG proof at point `z` for the polynomial represented by `Polynomial`.
    /// Do this by computing the quotient polynomial in evaluation form: q(x) = (p(x) - p(z)) / (x - z).
    pub fn compute_kzg_proof(
        &self,
        polynomial: &Polynomial,
        z_fr: &Fr,
    ) -> Result<G1Affine, KzgError> {
        if !self.params.completed_setup {
            return Err(KzgError::GenericError(
                "setup is not complete, run the data_setup functions".to_string(),
            ));
        }

        if polynomial.len() != self.expanded_roots_of_unity.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }
        
        self.compute_kzg_proof_impl(polynomial, z_fr)
    }

    /// refer to DA for more context
    pub fn compute_quotient_eval_on_domain(
        &self,
        z_fr: &Fr,
        eval_fr: &[Fr],
        value_fr: &Fr,
        roots_of_unity: &[Fr],
    ) -> Fr {
        let mut quotient = Fr::zero();
        let mut fi: Fr = Fr::zero();
        let mut numerator: Fr = Fr::zero();
        let mut denominator: Fr = Fr::zero();
        let mut temp: Fr = Fr::zero();

        roots_of_unity.iter().enumerate().for_each(|(i, omega_i)| {
            if *omega_i == *z_fr {
                return;
            }
            fi = eval_fr[i] - value_fr;
            numerator = fi * omega_i;
            denominator = z_fr - omega_i;
            denominator *= z_fr;
            temp = numerator.div(denominator);
            quotient += temp;
        });

        quotient
    }

    fn read_from_cache_if_exists(length: usize, cache_dir: &str) -> Vec<G1Affine> {
        // check if the cache_dir has the file with the length in it
        let cache_file = format!("{}/2_pow_{}.cache", cache_dir, length);
        if !cache_dir.is_empty()
            && check_directory(cache_dir).is_ok()
            && fs::metadata(&cache_file).is_ok()
        {
            match Self::parallel_read_g1_points_native(cache_file, length as u32, true) {
                Ok(points) => points,
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }

    // computes the IFFT, deserialize it and store it in file format.
    pub fn initialize_cache(&self, force: bool) -> Result<(), KzgError> {
        // powers of 2 from 10 to 20
        for length in 10..20_usize {
            let in_pow_2 = 2_u32.pow(length as u32);
            let cache_file = format!("{}/2_pow_{}.cache", self.cache_dir, in_pow_2);

            if fs::metadata(&cache_file).is_ok() && force {
                // Cache file already exists, delete it if force cache is set
                fs::remove_file(&cache_file)
                    .map_err(|err| KzgError::GenericError(err.to_string()))?;
            }

            let g1_ifft_points = self.g1_ifft(in_pow_2 as usize)?;

            let mut file =
                File::create(&cache_file).map_err(|err| KzgError::GenericError(err.to_string()))?;
            for point in g1_ifft_points {
                let mut serialized_point = vec![];
                point
                    .serialize_compressed(&mut serialized_point)
                    .map_err(|err| KzgError::SerializationError(err.to_string()))?;
                file.write_all(&serialized_point)
                    .map_err(|err| KzgError::SerializationError(err.to_string()))?;
            }
        }

        Ok(())
    }

    /// function to compute the inverse FFT
    pub fn g1_ifft(&self, length: usize) -> Result<Vec<G1Affine>, KzgError> {
        // is not power of 2
        if !length.is_power_of_two() {
            return Err(KzgError::FFTError(
                "length provided is not a power of 2".to_string(),
            ));
        }

        let cached_points = Self::read_from_cache_if_exists(length, &self.cache_dir);
        if cached_points.is_empty() {
            let points_projective: Vec<G1Projective> = self.g1[..length]
                .par_iter()
                .map(|&p| G1Projective::from(p))
                .collect();

            match GeneralEvaluationDomain::<Fr>::new(length) {
                Some(domain) => {
                    let ifft_result = domain.ifft(&points_projective);
                    let ifft_result_affine: Vec<_> =
                        ifft_result.par_iter().map(|p| p.into_affine()).collect();
                    Ok(ifft_result_affine)
                },
                None => Err(KzgError::FFTError(
                    "Could not perform IFFT due to domain consturction error".to_string(),
                )),
            }
        } else {
            Ok(cached_points)
        }
    }

    pub fn verify_kzg_proof(
        &self,
        commitment: G1Affine,
        proof: G1Affine,
        value_fr: Fr,
        z_fr: Fr,
    ) -> bool {
        let g2_tau = if self.g2.len() > 28 {
            *self.g2.get(1).unwrap()
        } else {
            *self.g2.first().unwrap()
        };
        let value_g1 = (G1Affine::generator() * value_fr).into_affine();
        let commit_minus_value = (commitment - value_g1).into_affine();
        let z_g2 = (G2Affine::generator() * z_fr).into_affine();
        let x_minus_z = (g2_tau - z_g2).into_affine();
        Self::pairings_verify(commit_minus_value, G2Affine::generator(), proof, x_minus_z)
    }

    pub fn get_g2_tau(&self) -> &G2Affine {
        if self.g2.len() > 28 {
            return self.g2.get(1).unwrap();
        } else {
            return self.g2.first().unwrap();
        };
    }

    fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
        let neg_b1 = -b1;
        let p = [a1, neg_b1];
        let q = [a2, b2];
        let result = Bn254::multi_pairing(p, q);
        result.is_zero()
    }

    /// Maps a byte slice to a field element (`Fr`) using SHA-256 from SHA3 family as the
    /// hash function.
    ///
    /// # Arguments
    ///
    /// * `msg` - The input byte slice to hash.
    ///
    /// # Returns
    ///
    /// * `Fr` - The resulting field element.
    fn hash_to_field_element(msg: &[u8]) -> Fr {
        // Perform the hash operation.
        let msg_digest = Sha256::digest(msg);
        let hash_elements = msg_digest.as_slice();

        let fr_element: Fr = match KZG_ENDIANNESS {
            Endianness::Big => Fr::from_be_bytes_mod_order(hash_elements),
            Endianness::Little => Fr::from_le_bytes_mod_order(hash_elements),
        };

        fr_element
    }

    /// Computes the Fiat-Shamir challenge from a blob and its commitment.
    ///
    /// # Arguments
    ///
    /// * `blob` - A reference to the `Blob` struct.
    /// * `commitment` - A reference to the `G1Affine` commitment.
    ///
    /// # Returns
    ///
    /// * `Ok(Fr)` - The resulting field element challenge.
    /// * `Err(KzgError)` - If any step fails.
    fn compute_challenge(blob: &Blob, commitment: &G1Affine) -> Result<Fr, KzgError> {
        let blob_poly = blob
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        let challenge_input_size: usize = FIAT_SHAMIR_PROTOCOL_DOMAIN.len()
            + 8
            + 8
            + (blob_poly.len() * BYTES_PER_FIELD_ELEMENT)
            + SIZE_OF_G1_AFFINE_COMPRESSED;
        let mut digest_bytes: Vec<u8> = vec![0; challenge_input_size];
        let mut offset = 0_usize;

        // Copy domain separator
        const DOMAIN_STR_LENGTH: usize = FIAT_SHAMIR_PROTOCOL_DOMAIN.len();

        digest_bytes[offset..DOMAIN_STR_LENGTH].copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN);
        offset += DOMAIN_STR_LENGTH;

        // Copy polynomial degree (16-bytes, big-endian)
        digest_bytes[offset..offset + 8].copy_from_slice(&0_u64.to_be_bytes());
        offset += 8;
        digest_bytes[offset..offset + 8].copy_from_slice(&(blob_poly.len() as u64).to_be_bytes());
        offset += 8;

        let bytes_per_blob: usize = blob_poly.len() * BYTES_PER_FIELD_ELEMENT;

        let blob_data = helpers::to_byte_array(
            &blob_poly.to_vec(),
            blob_poly.len() * BYTES_PER_FIELD_ELEMENT,
        );
        digest_bytes[offset..offset + bytes_per_blob].copy_from_slice(blob_data.as_slice());
        offset += bytes_per_blob;

        // Copy commitment
        let mut commitment_bytes = Vec::with_capacity(32);
        commitment
            .serialize_compressed(&mut commitment_bytes)
            .map_err(|_| KzgError::SerializationError("Failed to serialize commitment".to_string()))
            .unwrap();

        digest_bytes[offset..offset + SIZE_OF_G1_AFFINE_COMPRESSED]
            .copy_from_slice(&commitment_bytes);
        offset += SIZE_OF_G1_AFFINE_COMPRESSED;

        /* Make sure we wrote the entire buffer */
        if offset != challenge_input_size {
            return Err(KzgError::InvalidInputLength);
        }
        let evaluation_fr = Self::hash_to_field_element(&digest_bytes);
        Ok(evaluation_fr)
    }

    fn evaluate_polynomial_in_evaluation_form(
        polynomial: &Polynomial,
        z: &Fr,
        srs_order: u64,
    ) -> Result<Fr, KzgError> {
        // Step 1: Retrieve the length of the padded blob
        let blob_size = polynomial.get_length_of_padded_blob();

        // Step 2: Calculate roots of unity for the given blob size and SRS order
        let (_, roots_of_unity) =
            Self::calculate_roots_of_unity_non_assign(blob_size as u64, srs_order)?;

        // Step 3: Ensure the polynomial length matches the domain length
        if polynomial.len() != roots_of_unity.len() {
            return Err(KzgError::InvalidInputLength);
        }

        let width = polynomial.len();

        // Step 4: Compute inverse_width = 1 / width
        let inverse_width = Fr::from(width as u64)
            .inverse()
            .ok_or(KzgError::InvalidDenominator)?;

        // Step 5: Check if `z` is in the domain
        if let Some(index) = roots_of_unity.iter().position(|&domain_i| domain_i == *z) {
            return polynomial
                .get_at_index(index)
                .cloned()
                .ok_or(KzgError::GenericError(
                    "Polynomial element missing at the found index.".to_string(),
                ));
        }

        // Step 6: Use the barycentric formula to compute the evaluation
        let sum = polynomial
            .to_vec()
            .iter()
            .zip(roots_of_unity.iter())
            .map(|(f_i, &domain_i)| {
                let a = *f_i * domain_i;
                let b = *z - domain_i;
                // Since `z` is not in the domain, `b` should never be zero
                a / b
            })
            .fold(Fr::zero(), |acc, val| acc + val);

        // Step 7: Compute r = z^width - 1
        let r = z.pow([width as u64]) - Fr::one();

        // Step 8: Compute f(z) = (z^width - 1) / width * sum
        let f_z = sum * r * inverse_width;

        Ok(f_z)
    }

    fn compute_challenges_and_evaluate_polynomial(
        blobs: Vec<Blob>,
        commitments: &[G1Affine],
        srs_order: u64,
    ) -> Result<(Vec<Fr>, Vec<Fr>), KzgError> {
        // Initialize vectors to store evaluation challenges and polynomial evaluations
        let mut evaluation_challenges = Vec::with_capacity(blobs.len());
        let mut ys = Vec::with_capacity(blobs.len());

        // Iterate over each blob to compute its polynomial evaluation
        // TODO: There are some cache optimizations that can be done here for the roots of unities calculations.
        //       Also depending on the size of blobs, this can be parallelized for some gains.
        for i in 0..blobs.len() {
            // Convert the blob to its polynomial representation
            let polynomial = blobs[i]
                .to_polynomial(PolynomialFormat::InCoefficientForm)
                .unwrap();

            // Compute the Fiat-Shamir challenge for the current blob and its commitment
            let evaluation_challenge = Self::compute_challenge(&blobs[i], &commitments[i])?;
            // Evaluate the polynomial at the computed challenge
            let y = Self::evaluate_polynomial_in_evaluation_form(
                &polynomial,
                &evaluation_challenge,
                srs_order,
            )?;

            // Store the evaluation challenge and the polynomial evaluation
            evaluation_challenges.push(evaluation_challenge);
            ys.push(y);
        }

        // Return the vectors of evaluation challenges and polynomial evaluations
        Ok((evaluation_challenges, ys))
    }

    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &G1Affine,
        proof: &G1Affine,
    ) -> Result<bool, KzgError> {
        // Convert blob to polynomial
        let polynomial = blob
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();

        // Compute the evaluation challenge for the blob and commitment
        let evaluation_challenge = Self::compute_challenge(blob, commitment)?;

        // Evaluate the polynomial in evaluation form
        let y = Self::evaluate_polynomial_in_evaluation_form(
            &polynomial,
            &evaluation_challenge,
            self.srs_order,
        )?;

        // Verify the KZG proof
        Ok(self.verify_kzg_proof(*commitment, *proof, y, evaluation_challenge))
    }

    pub fn compute_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &G1Affine,
    ) -> Result<G1Affine, KzgError> {
        if !blob.is_padded() {
            return Err(KzgError::GenericError(
                "blob needs to be padded".to_string(),
            ));
        }

        if !is_on_curve_g1(&G1Projective::from(*commitment)) {
            return Err(KzgError::GenericError(
                "commitment not on curve".to_string(),
            ));
        }

        let blob_poly = blob
            .to_polynomial(PolynomialFormat::InCoefficientForm)
            .unwrap();
        let evaluation_challenge = Self::compute_challenge(blob, commitment)?;
        self.compute_kzg_proof_impl(&blob_poly, &evaluation_challenge)
    }

    pub fn verify_blob_kzg_proof_batch(
        blobs: &Vec<Blob>,
        commitments: &Vec<G1Affine>,
        proofs: &Vec<G1Affine>,
        srs_order: u64,
        g2_tau: &G2Affine,
    ) -> Result<bool, KzgError> {
        if !(commitments.len() == blobs.len() && proofs.len() == blobs.len()) {
            return Err(KzgError::GenericError(
                "length's of the input are not the same".to_owned(),
            ));
        }

        if !blobs.iter().all(|blob| blob.is_padded()) {
            return Err(BlobError::GenericError("blob not padded".to_owned()).into());
        }

        if !commitments
            .iter()
            .all(|commitment| is_on_curve_g1(&G1Projective::from(*commitment)))
        {
            return Err(KzgError::CommitmentError(
                "commitment not on curve".to_owned(),
            ));
        }

        if !proofs
            .iter()
            .all(|proof| is_on_curve_g1(&G1Projective::from(*proof)))
        {
            return Err(KzgError::CommitmentError("proof not on curve".to_owned()));
        }

        if blobs.len() != commitments.len() && proofs.len() != blobs.len() {
            return Err(KzgError::GenericError(
                "the number of blobs, 
            commitments and proofs need to be of the same"
                    .to_owned(),
            ));
        }

        let (evaluation_challenges, ys) = Self::compute_challenges_and_evaluate_polynomial(
            blobs.to_vec(),
            commitments,
            srs_order,
        )?;

        // Perform batch verification.
        Self::verify_kzg_proof_batch(commitments, &evaluation_challenges, &ys, proofs, g2_tau)
    }

    fn compute_r_powers(
        commitment: &[G1Affine],
        zs: &[Fr],
        ys: &[Fr],
        proofs: &[G1Affine],
    ) -> Result<Vec<Fr>, KzgError> {
        let n = commitment.len();
        let mut initial_data_length: usize = 40;
        let input_size = initial_data_length
            + n * (BYTES_PER_FIELD_ELEMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT);

        let mut data_to_be_hashed: Vec<u8> = vec![0; input_size];

        // Copy domain separator
        data_to_be_hashed[..24].copy_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);

        data_to_be_hashed[24..32].copy_from_slice(&(FIELD_ELEMENTS_PER_BLOB).to_be_bytes());

        // Assign n_bytes to bytes[32..40]
        let mut n_bytes = n.to_be_bytes().to_vec();
        n_bytes.resize(8, 0);
        data_to_be_hashed[32..40].copy_from_slice(&n_bytes);

        for i in 0..n {
            // Copy commitment
            let mut v = vec![];
            commitment[i].serialize_compressed(&mut v).map_err(|_| {
                KzgError::SerializationError("Failed to serialize commitment".to_string())
            })?;

            data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
                .copy_from_slice(&v[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;

            // Copy evaluation challenge
            let v = zs[i].into_bigint().to_bytes_be();
            data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
                .copy_from_slice(&v[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;

            // Copy polynomial's evaluation value
            let v = ys[i].into_bigint().to_bytes_be();
            data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
                .copy_from_slice(&v[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;

            // Copy proof
            let mut proof_bytes = vec![];
            proofs[i]
                .serialize_compressed(&mut proof_bytes)
                .map_err(|_| {
                    KzgError::SerializationError("Failed to serialize proof".to_string())
                })?;
            data_to_be_hashed[initial_data_length..(proof_bytes.len() + initial_data_length)]
                .copy_from_slice(&proof_bytes[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;
        }

        // Make sure we wrote the entire buffer
        if initial_data_length != input_size {
            return Err(KzgError::InvalidInputLength);
        }

        let r = Self::hash_to_field_element(&data_to_be_hashed);

        Ok(helpers::compute_powers(&r, n))
    }

    /// Verifies multiple KZG proofs efficiently.
    ///
    /// # Arguments
    ///
    /// * `commitments` - A slice of `G1Affine` commitments.
    /// * `zs` - A slice of `Fr` elements representing z values.
    /// * `ys` - A slice of `Fr` elements representing y values.
    /// * `proofs` - A slice of `G1Affine` proofs.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if all proofs are valid.
    /// * `Ok(false)` if any proof is invalid.
    /// * `Err(KzgError)` if an error occurs during verification.
    pub fn verify_kzg_proof_batch(
        commitments: &[G1Affine],
        zs: &[Fr],
        ys: &[Fr],
        proofs: &[G1Affine],
        g2_tau: &G2Affine,
    ) -> Result<bool, KzgError> {
        if !(commitments.len() == zs.len() && zs.len() == ys.len() && ys.len() == proofs.len()) {
            return Err(KzgError::GenericError(
                "length's of the input are not the same".to_owned(),
            ));
        }

        if !commitments
            .iter()
            .all(|commitment| is_on_curve_g1(&G1Projective::from(*commitment)))
        {
            return Err(KzgError::NotOnCurveError(
                "commitment not on curve".to_owned(),
            ));
        }

        if !proofs
            .iter()
            .all(|proof| is_on_curve_g1(&G1Projective::from(*proof)))
        {
            return Err(KzgError::NotOnCurveError("proof".to_owned()));
        }

        if !is_on_curve_g2(&G2Projective::from(*g2_tau)) {
            return Err(KzgError::NotOnCurveError("g2 tau".to_owned()));
        }

        let n = commitments.len();

        // Initialize vectors to store intermediate values
        let mut c_minus_y: Vec<G1Affine> = Vec::with_capacity(n);
        let mut r_times_z: Vec<Fr> = Vec::with_capacity(n);

        // Compute r powers
        let r_powers = Self::compute_r_powers(commitments, zs, ys, proofs)?;

        // Compute proof linear combination
        let proof_lincomb = helpers::g1_lincomb(proofs, &r_powers);

        // Compute c_minus_y and r_times_z
        for i in 0..n {
            let ys_encrypted = G1Affine::generator() * ys[i];
            c_minus_y.push((commitments[i] - ys_encrypted).into_affine());
            r_times_z.push(r_powers[i] * zs[i]);
        }

        // Compute proof_z_lincomb and c_minus_y_lincomb
        let proof_z_lincomb = helpers::g1_lincomb(proofs, &r_times_z);
        let c_minus_y_lincomb = helpers::g1_lincomb(&c_minus_y, &r_powers);

        // Compute rhs_g1
        let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

        // Verify the pairing equation
        let result =
            Self::pairings_verify(proof_lincomb, *g2_tau, rhs_g1.into(), G2Affine::generator());
        Ok(result)
    }
}
