use crate::{
    blob::Blob,
    consts::{BYTES_PER_FIELD_ELEMENT, SIZE_OF_G1_AFFINE_COMPRESSED},
    errors::KzgError,
    helpers,
    polynomial::{PolynomialCoeffForm, PolynomialEvalForm},
    traits::ReadPointFromBytes,
};

use crate::consts::{
    Endianness, FIAT_SHAMIR_PROTOCOL_DOMAIN, KZG_ENDIANNESS, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN,
};
use crate::helpers::is_on_curve_g1;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalSerialize, Read};
use ark_std::{iterable::Iterable, ops::Div, str::FromStr, One, Zero};
use crossbeam_channel::{bounded, Sender};
use num_traits::ToPrimitive;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, BufReader},
};

/// Main interesting struct of the rust-kzg-bn254 crate.
/// [Kzg] is a struct that holds the SRS points in monomial form, and
/// provides methods for committing to a blob, (either via a [Blob] itself,
/// or a [PolynomialCoeffForm] or [PolynomialEvalForm]), and generating and
/// verifying proofs.
///
/// The [Blob] and [PolynomialCoeffForm]/[PolynomialEvalForm] structs are mostly
/// <https://en.wikipedia.org/wiki/Passive_data_structure> with
/// constructor and few helper methods.
#[derive(Debug, PartialEq, Clone)]
pub struct KZG {
    // SRS points are stored in monomial form, ready to be used for commitments with polynomials
    // in coefficient form. To commit against a polynomial in evaluation form, we need to transform
    // the SRS points to lagrange form using IFFT.
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    params: Params,
    srs_order: u64,
    expanded_roots_of_unity: Vec<Fr>,
}

#[derive(Debug, PartialEq, Clone)]
struct Params {
    max_fft_width: u64,
    completed_setup: bool,
}

impl KZG {
    pub fn setup(
        path_to_g1_points: &str,
        path_to_g2_points: &str,
        g2_power_of2_path: &str,
        srs_order: u32,
        srs_points_to_load: u32,
    ) -> Result<Self, KzgError> {
        if srs_points_to_load > srs_order {
            return Err(KzgError::GenericError(
                "number of points to load is more than the srs order".to_string(),
            ));
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
                max_fft_width: 0,
                completed_setup: false,
            },
            srs_order: srs_order.into(),
            expanded_roots_of_unity: vec![],
        })
    }

    pub fn read_g2_point_on_power_of_2(g2_power_of2_path: &str) -> Result<Vec<G2Affine>, KzgError> {
        let mut file =
            File::open(g2_power_of2_path).map_err(|e| KzgError::GenericError(e.to_string()))?;

        // Calculate the start position in bytes and seek to that position
        // Read in 64-byte chunks
        let mut chunks = Vec::new();
        let mut buffer = [0u8; 64];
        loop {
            let bytes_read = file
                .read(&mut buffer)
                .map_err(|e| KzgError::GenericError(e.to_string()))?;
            if bytes_read == 0 {
                break; // End of file reached
            }
            chunks.push(
                G2Affine::read_point_from_bytes_be(&buffer[..bytes_read])
                    .map_err(|e| KzgError::GenericError(e.to_string()))?,
            );
        }
        Ok(chunks)
    }

    /// Calculates the roots of unities but doesn't assign it to the struct
    /// Used in batch verification process as the roots need to be calculated for each blob
    /// because of different length.
    ///
    /// # Arguments
    /// * `length_of_data_after_padding` - Length of the blob data after padding in bytes.
    ///
    /// # Returns
    /// * `Result<(Params, Vec<Fr>), KzgError>` - Tuple containing:
    ///   - Params: KZG library operational parameters
    ///   - Vec<Fr>: Vector of roots of unity
    ///
    /// # Details
    /// - Generates roots of unity needed for FFT operations
    /// - Calculates KZG operational parameters for commitment scheme
    ///
    /// # Example
    /// ```
    /// use ark_std::One;
    /// use rust_kzg_bn254::helpers::to_byte_array;
    /// use ark_bn254::Fr;
    ///
    /// let elements = vec![Fr::one(), Fr::one(), Fr::one()];
    /// let max_size = 64;
    /// let bytes = to_byte_array(&elements, max_size);
    /// assert_eq!(bytes.len(), 64);
    /// // bytes will contain up to max_size bytes from the encoded elements
    /// ```
    fn calculate_roots_of_unity_standalone(
        length_of_data_after_padding: u64,
        srs_order: u64,
    ) -> Result<(Params, Vec<Fr>), KzgError> {
        // Initialize parameters
        let mut params = Params {
            max_fft_width: 0_u64,
            completed_setup: false,
        };

        // Calculate log2 of the next power of two of the length of data after padding
        let log2_of_evals = (length_of_data_after_padding
            .div_ceil(32)
            .next_power_of_two() as f64)
            .log2()
            .to_u8()
            .ok_or_else(|| {
                KzgError::GenericError(
                    "Failed to convert length_of_data_after_padding to u8".to_string(),
                )
            })?;

        // Set the maximum FFT width
        params.max_fft_width = 1_u64 << log2_of_evals;

        // Check if the length of data after padding is valid with respect to the SRS order
        if length_of_data_after_padding
            .div_ceil(BYTES_PER_FIELD_ELEMENT as u64)
            .next_power_of_two()
            > srs_order
        {
            return Err(KzgError::SerializationError(
                "the supplied encoding parameters are not valid with respect to the SRS."
                    .to_string(),
            ));
        }

        // Get the primitive roots of unity
        let primitive_roots_of_unity = Self::get_primitive_roots_of_unity()?;

        // Find the root of unity corresponding to the calculated log2 value
        let found_root_of_unity = primitive_roots_of_unity
            .get(log2_of_evals as usize)
            .ok_or_else(|| KzgError::GenericError("Root of unity not found".to_string()))?;

        // Expand the root to get all the roots of unity
        let mut expanded_roots_of_unity = Self::expand_root_of_unity(found_root_of_unity);

        // Remove the last element to avoid duplication
        expanded_roots_of_unity.truncate(expanded_roots_of_unity.len() - 1);

        // Mark the setup as completed
        params.completed_setup = true;

        // Return the parameters and the expanded roots of unity
        Ok((params, expanded_roots_of_unity))
    }

    pub fn calculate_roots_of_unity(
        &mut self,
        length_of_data_after_padding: u64,
    ) -> Result<(), KzgError> {
        let (params, roots_of_unity) = Self::calculate_roots_of_unity_standalone(
            length_of_data_after_padding,
            self.srs_order,
        )?;
        self.params = params;
        self.params.completed_setup = true;
        self.expanded_roots_of_unity = roots_of_unity;
        Ok(())
    }

    pub fn get_roots_of_unities(&self) -> Vec<Fr> {
        self.expanded_roots_of_unity.clone()
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

    /// Precompute the primitive roots of unity for binary powers that divide r - 1
    /// TODO(anupsv): Move this to the constants file. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/31
    fn get_primitive_roots_of_unity() -> Result<Vec<Fr>, KzgError> {
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
            .map(Fr::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                KzgError::GenericError("Failed to parse primitive roots of unity".to_string())
            })
    }

    /// helper function to get g1 points
    pub fn get_g1_points(&self) -> Vec<G1Affine> {
        self.g1.to_vec()
    }

    /// read files in chunks with specified length
    /// TODO: chunks seems misleading here, since we read one field element at a
    /// time.
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
        // FIXME: Read the entire file (or large segments) into memory and then split it
        // into field elements. Entire G1 file might be ~8GiB, so might not fit
        // in RAM. But we can only read the subset of the file that we need.
        // For eg. for fault proof usage, only need to read 32MiB if our blob size is
        // that large.
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

    /// read G1 points in parallel, by creating one reader thread, which reads
    /// bytes from the file, and fans them out to worker threads (one per
    /// cpu) which parse the bytes into G1Affine points. The worker threads
    /// then fan in the parsed points to the main thread, which sorts them by
    /// their original position in the file to maintain order. Not used anywhere
    /// but kept as a reference.
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
        // Channel contains (bytes, position, is_native) tuples. The position is used to
        // reorder the points after processing them.
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

    /// Commit the polynomial with the srs values loaded into [Kzg].
    pub fn commit_eval_form(&self, polynomial: &PolynomialEvalForm) -> Result<G1Affine, KzgError> {
        if polynomial.len() > self.g1.len() {
            return Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string(),
            ));
        }

        // When the polynomial is in evaluation form, use IFFT to transform monomial srs
        // points to lagrange form.
        let bases = self.g1_ifft(polynomial.len())?;

        match G1Projective::msm(&bases, polynomial.evaluations()) {
            Ok(res) => Ok(res.into_affine()),
            Err(err) => Err(KzgError::CommitError(err.to_string())),
        }
    }

    /// Commit the polynomial with the srs values loaded into [Kzg].
    pub fn commit_coeff_form(
        &self,
        polynomial: &PolynomialCoeffForm,
    ) -> Result<G1Affine, KzgError> {
        if polynomial.len() > self.g1.len() {
            return Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string(),
            ));
        }
        // When the polynomial is in coefficient form, use the original srs points (in
        // monomial form).
        let bases = self.g1[..polynomial.len()].to_vec();

        match G1Projective::msm(&bases, polynomial.coeffs()) {
            Ok(res) => Ok(res.into_affine()),
            Err(err) => Err(KzgError::CommitError(err.to_string())),
        }
    }

    /// Helper function for `compute_kzg_proof()` and `compute_blob_kzg_proof()`
    fn compute_proof_impl(
        &self,
        polynomial: &PolynomialEvalForm,
        z_fr: &Fr,
    ) -> Result<G1Affine, KzgError> {
        if !self.params.completed_setup {
            return Err(KzgError::GenericError(
                "setup is not complete, run the data_setup functions".to_string(),
            ));
        }

        // Verify polynomial length matches that of the roots of unity
        if polynomial.len() != self.expanded_roots_of_unity.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }

        let eval_fr = polynomial.evaluations();
        // Pre-allocate vector for shifted polynomial p(x) - y
        let mut poly_shift: Vec<Fr> = Vec::with_capacity(eval_fr.len());

        // Evaluate polynomial at the point z
        // This gives us y = p(z)
        let y_fr = Self::evaluate_polynomial_in_evaluation_form(polynomial, z_fr, self.srs_order)?;

        // Compute p(x) - y for each evaluation point
        // This is the numerator of the quotient polynomial
        for fr in eval_fr {
            poly_shift.push(*fr - y_fr);
        }

        // Compute denominator polynomial (x - z) at each root of unity
        let mut denom_poly = Vec::<Fr>::with_capacity(self.expanded_roots_of_unity.len());
        for root_of_unity in self.expanded_roots_of_unity.iter().take(eval_fr.len()) {
            denom_poly.push(*root_of_unity - z_fr);
        }

        // Pre-allocate vector for quotient polynomial evaluations
        let mut quotient_poly = Vec::<Fr>::with_capacity(self.expanded_roots_of_unity.len());

        // Compute quotient polynomial q(x) = (p(x) - y)/(x - z) at each root of unity
        for i in 0..self.expanded_roots_of_unity.len() {
            if denom_poly[i].is_zero() {
                // Special case: when x = z, use L'Hôpital's rule
                // Compute the derivative evaluation instead
                quotient_poly.push(self.compute_quotient_eval_on_domain(z_fr, eval_fr, &y_fr));
            } else {
                // Normal case: direct polynomial division
                quotient_poly.push(poly_shift[i].div(denom_poly[i]));
            }
        }

        let quotient_poly_eval_form = PolynomialEvalForm::new(quotient_poly);
        self.commit_eval_form(&quotient_poly_eval_form)
    }

    /// commit to a [Blob], by transforming it into a [PolynomialEvalForm] and
    /// then calling [Kzg::commit_eval_form].
    pub fn commit_blob(&self, blob: &Blob) -> Result<G1Affine, KzgError> {
        let polynomial = blob.to_polynomial_eval_form();
        self.commit_eval_form(&polynomial)
    }

    pub fn compute_proof_with_known_z_fr_index(
        &self,
        polynomial: &PolynomialEvalForm,
        index: u64,
    ) -> Result<G1Affine, KzgError> {
        // Convert u64 index to usize for array indexing
        let usized_index = index.to_usize().ok_or(KzgError::GenericError(
            "Index conversion to usize failed".to_string(),
        ))?;

        // Get the root of unity at the specified index
        let z_fr = self
            .get_nth_root_of_unity(usized_index)
            .ok_or_else(|| KzgError::GenericError("Root of unity not found".to_string()))?;

        // Compute the KZG proof at the selected root of unity
        // This delegates to the main proof computation function
        // using our selected evaluation point
        self.compute_proof(polynomial, z_fr)
    }

    /// Compute a kzg proof from a polynomial in evaluation form.
    /// We don't currently support proofs for polynomials in coefficient form,
    /// but one can take the FFT of the polynomial in coefficient form to
    /// get the polynomial in evaluation form. This is available via the
    /// method [PolynomialCoeffForm::to_eval_form].
    /// TODO(anupsv): Accept bytes instead of Fr element. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/29
    pub fn compute_proof(
        &self,
        polynomial: &PolynomialEvalForm,
        z_fr: &Fr,
    ) -> Result<G1Affine, KzgError> {
        if !self.params.completed_setup {
            return Err(KzgError::GenericError(
                "setup is not complete, run one of the setup functions".to_string(),
            ));
        }

        // Verify that polynomial length matches roots of unity length
        if polynomial.len() != self.expanded_roots_of_unity.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }

        // Call the implementation to compute the actual proof
        // This will:
        // 1. Evaluate polynomial at z
        // 2. Compute quotient polynomial q(x) = (p(x) - p(z)) / (x - z)
        // 3. Generate KZG proof as commitment to q(x)
        self.compute_proof_impl(polynomial, z_fr)
    }

    /// refer to DA for more context
    pub fn compute_quotient_eval_on_domain(&self, z_fr: &Fr, eval_fr: &[Fr], value_fr: &Fr) -> Fr {
        let mut quotient = Fr::zero();
        let mut fi: Fr = Fr::zero();
        let mut numerator: Fr = Fr::zero();
        let mut denominator: Fr = Fr::zero();
        let mut temp: Fr = Fr::zero();

        self.expanded_roots_of_unity
            .iter()
            .enumerate()
            .for_each(|(i, omega_i)| {
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

    /// function to compute the inverse FFT
    pub fn g1_ifft(&self, length: usize) -> Result<Vec<G1Affine>, KzgError> {
        // is not power of 2
        if !length.is_power_of_two() {
            return Err(KzgError::FFTError(
                "length provided is not a power of 2".to_string(),
            ));
        }

        let points_projective: Vec<G1Projective> = self.g1[..length]
            .par_iter()
            .map(|&p| G1Projective::from(p))
            .collect();
        let ifft_result: Vec<_> = GeneralEvaluationDomain::<Fr>::new(length)
            .ok_or(KzgError::FFTError(
                "Could not perform IFFT due to domain consturction error".to_string(),
            ))?
            .ifft(&points_projective)
            .par_iter()
            .map(|p| p.into_affine())
            .collect();

        Ok(ifft_result)
    }

    /// TODO(anupsv): Accept bytes instead of Fr element and Affine points. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/30
    pub fn verify_proof(
        &self,
        commitment: G1Affine,
        proof: G1Affine,
        value_fr: Fr,
        z_fr: Fr,
    ) -> Result<bool, KzgError> {
        // Get τ*G2 from the trusted setup
        // This is the second generator point multiplied by the trusted setup secret
        let g2_tau = self.get_g2_tau()?;

        // Compute [value]*G1
        // This encrypts the claimed evaluation value as a point in G1
        let value_g1 = (G1Affine::generator() * value_fr).into_affine();

        // Compute [C - value*G1]
        // This represents the difference between the commitment and claimed value
        // If the claim is valid, this equals H(X)(X - z) in the polynomial equation
        let commit_minus_value = (commitment - value_g1).into_affine();

        // Compute [z]*G2
        // This encrypts the evaluation point as a point in G2
        let z_g2 = (G2Affine::generator() * z_fr).into_affine();

        // Compute [τ - z]*G2
        // This represents (X - z) in the polynomial equation
        // τ is the secret from the trusted setup representing the variable X
        let x_minus_z = (*g2_tau - z_g2).into_affine();

        // Verify the pairing equation:
        // e([C - value*G1], G2) = e(proof, [τ - z]*G2)
        // This checks if (C - value*G1) = proof * (τ - z)
        // which verifies the polynomial quotient relationship
        Ok(Self::pairings_verify(
            commit_minus_value,    // Left side first argument
            G2Affine::generator(), // Left side second argument (G2 generator)
            proof,                 // Right side first argument
            x_minus_z,             // Right side second argument
        ))
    }

    pub fn get_g2_tau(&self) -> Result<&G2Affine, KzgError> {
        if self.g2.len() > 28 {
            self.g2
                .get(1)
                .ok_or(KzgError::GenericError("g2 tau not found".to_string()))
        } else {
            self.g2
                .first()
                .ok_or(KzgError::GenericError("g2 tau not found".to_string()))
        }
    }

    fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
        let neg_b1 = -b1;
        let p = [a1, neg_b1];
        let q = [a2, b2];
        let result = Bn254::multi_pairing(p, q);
        result.is_zero()
    }

    /// TODO(anupsv): Accept bytes instead of Affine points. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/31
    pub fn verify_blob_kzg_proof(
        &self,
        blob: &Blob,
        commitment: &G1Affine,
        proof: &G1Affine,
    ) -> Result<bool, KzgError> {
        // Convert blob to polynomial
        let polynomial = blob.to_polynomial_eval_form();

        // Compute the evaluation challenge for the blob and commitment
        let evaluation_challenge = Self::compute_challenge(blob, commitment)?;

        // Evaluate the polynomial in evaluation form
        let y = Self::evaluate_polynomial_in_evaluation_form(
            &polynomial,
            &evaluation_challenge,
            self.srs_order,
        )?;

        // Verify the KZG proof
        self.verify_proof(*commitment, *proof, y, evaluation_challenge)
    }

    /// TODO(anupsv): Match 4844 specs w.r.t to the inputs. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/30
    pub fn compute_blob_proof(
        &self,
        blob: &Blob,
        commitment: &G1Affine,
    ) -> Result<G1Affine, KzgError> {
        // Validate that the commitment is a valid point on the G1 curve
        // This prevents potential invalid curve attacks
        if !commitment.is_on_curve() || !commitment.is_in_correct_subgroup_assuming_on_curve() {
            return Err(KzgError::NotOnCurveError(
                "commitment not on curve".to_string(),
            ));
        }

        // Convert the blob to a polynomial in evaluation form
        // This is necessary because KZG proofs work with polynomials
        let blob_poly = blob.to_polynomial_eval_form();

        // Compute the evaluation challenge using Fiat-Shamir heuristic
        // This challenge determines the point at which we evaluate the polynomial
        let evaluation_challenge = Self::compute_challenge(blob, commitment)?;

        // Compute the actual KZG proof using the polynomial and evaluation point
        // This creates a proof that the polynomial evaluates to a specific value at the challenge point
        // The proof is a single G1 point that can be used to verify the evaluation
        self.compute_proof_impl(&blob_poly, &evaluation_challenge)
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

        // TODO(anupsv): To be removed and default to Big endian. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/27
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
    pub fn compute_challenge(blob: &Blob, commitment: &G1Affine) -> Result<Fr, KzgError> {
        // Convert the blob to a polynomial in evaluation form
        // This is needed to process the blob data for the challenge
        let blob_poly = blob.to_polynomial_eval_form();

        // Calculate total size needed for the challenge input buffer:
        // - Length of domain separator
        // - 8 bytes for number of field elements
        // - Size of blob data (number of field elements * bytes per element)
        // - Size of compressed G1 point (commitment)
        let challenge_input_size = FIAT_SHAMIR_PROTOCOL_DOMAIN.len()
            + 8
            + (blob_poly.len() * BYTES_PER_FIELD_ELEMENT)
            + SIZE_OF_G1_AFFINE_COMPRESSED;

        // Initialize buffer to store all data that will be hashed
        let mut digest_bytes = vec![0; challenge_input_size];
        let mut offset = 0;

        // Step 1: Copy the Fiat-Shamir domain separator
        // This provides domain separation for the hash function to prevent
        // attacks that try to confuse different protocol messages
        digest_bytes[offset..offset + FIAT_SHAMIR_PROTOCOL_DOMAIN.len()]
            .copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN);
        offset += FIAT_SHAMIR_PROTOCOL_DOMAIN.len();

        // Step 2: Copy the number of field elements (blob polynomial length)
        // Convert to bytes using the configured endianness
        // TODO(anupsv): To be removed and default to Big endian. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/27
        let number_of_field_elements = match KZG_ENDIANNESS {
            Endianness::Big => blob_poly.len().to_be_bytes(),
            Endianness::Little => blob_poly.len().to_le_bytes(),
        };
        digest_bytes[offset..offset + 8].copy_from_slice(&number_of_field_elements);
        offset += 8;

        // Step 3: Copy the blob data
        // Convert polynomial to bytes using helper function
        let blob_data = helpers::to_byte_array(
            blob_poly.evaluations(),
            blob_poly.len() * BYTES_PER_FIELD_ELEMENT,
        );
        digest_bytes[offset..offset + blob_data.len()].copy_from_slice(&blob_data);
        offset += blob_data.len();

        // Step 4: Copy the commitment (compressed G1 point)
        // Serialize the commitment point in compressed form
        let mut commitment_bytes = Vec::with_capacity(SIZE_OF_G1_AFFINE_COMPRESSED);
        commitment
            .serialize_compressed(&mut commitment_bytes)
            .map_err(|_| {
                KzgError::SerializationError("Failed to serialize commitment".to_string())
            })?;
        digest_bytes[offset..offset + SIZE_OF_G1_AFFINE_COMPRESSED]
            .copy_from_slice(&commitment_bytes);

        // Verify that we wrote exactly the amount of bytes we expected
        // This helps catch any buffer overflow/underflow bugs
        if offset + SIZE_OF_G1_AFFINE_COMPRESSED != challenge_input_size {
            return Err(KzgError::InvalidInputLength);
        }

        // Hash all the data to generate the challenge field element
        // This implements the Fiat-Shamir transform to generate a "random" challenge
        Ok(Self::hash_to_field_element(&digest_bytes))
    }

    /// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#evaluate_polynomial_in_evaluation_form
    pub fn evaluate_polynomial_in_evaluation_form(
        polynomial: &PolynomialEvalForm,
        z: &Fr,
        srs_order: u64,
    ) -> Result<Fr, KzgError> {
        // Step 1: Retrieve the length of the padded blob
        let blob_size = polynomial.len_underlying_blob_bytes();

        // Step 2: Calculate roots of unity for the given blob size and SRS order
        let (_, roots_of_unity) =
            Self::calculate_roots_of_unity_standalone(blob_size as u64, srs_order)?;

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
                .get_evalualtion(index)
                .cloned()
                .ok_or(KzgError::GenericError(
                    "Polynomial element missing at the found index.".to_string(),
                ));
        }

        // Step 6: Use the barycentric formula to compute the evaluation
        let sum = polynomial
            .evaluations()
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

    /// A helper function for the `verify_blob_kzg_proof_batch` function.
    fn compute_challenges_and_evaluate_polynomial(
        blobs: &[Blob],
        commitments: &[G1Affine],
        srs_order: u64,
    ) -> Result<(Vec<Fr>, Vec<Fr>), KzgError> {
        // Pre-allocate vectors to store:
        // - evaluation_challenges: Points where polynomials will be evaluated
        // - ys: Results of polynomial evaluations at challenge points
        let mut evaluation_challenges = Vec::with_capacity(blobs.len());
        let mut ys = Vec::with_capacity(blobs.len());

        // Process each blob sequentially
        // TODO: Potential optimizations:
        // 1. Cache roots of unity calculations across iterations
        // 2. Parallelize processing for large numbers of blobs
        // 3. Batch polynomial conversions if possible
        for i in 0..blobs.len() {
            // Step 1: Convert blob to polynomial form
            // This is necessary because we need to evaluate the polynomial
            let polynomial = blobs[i].to_polynomial_eval_form();

            // Step 2: Generate Fiat-Shamir challenge
            // This creates a "random" evaluation point based on the blob and commitment
            // The challenge is deterministic but unpredictable, making the proof non-interactive
            let evaluation_challenge = Self::compute_challenge(&blobs[i], &commitments[i])?;

            // Step 3: Evaluate the polynomial at the challenge point
            // This uses the evaluation form for efficient computation
            // The srs_order parameter ensures compatibility with the trusted setup
            let y = Self::evaluate_polynomial_in_evaluation_form(
                &polynomial,
                &evaluation_challenge,
                srs_order,
            )?;

            // Store both:
            // - The challenge point (where we evaluated)
            // - The evaluation result (what the polynomial equals at that point)
            evaluation_challenges.push(evaluation_challenge);
            ys.push(y);
        }

        // Return tuple of:
        // 1. Vector of evaluation points (challenges)
        // 2. Vector of polynomial evaluations at those points
        // These will be used in the KZG proof verification process
        Ok((evaluation_challenges, ys))
    }

    /// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof_batch
    pub fn verify_blob_kzg_proof_batch(
        &self,
        blobs: &Vec<Blob>,
        commitments: &Vec<G1Affine>,
        proofs: &Vec<G1Affine>,
    ) -> Result<bool, KzgError> {
        // First validation check: Ensure all input vectors have matching lengths
        // This is critical for batch verification to work correctly
        if !(commitments.len() == blobs.len() && proofs.len() == blobs.len()) {
            return Err(KzgError::GenericError(
                "length's of the input are not the same".to_owned(),
            ));
        }

        // Validate that all commitments are valid points on the G1 curve
        // Using parallel iterator (par_iter) for better performance on large batches
        // This prevents invalid curve attacks
        if commitments.iter().any(|commitment| {
            commitment == &G1Affine::identity()
                || !commitment.is_on_curve()
                || !commitment.is_in_correct_subgroup_assuming_on_curve()
        }) {
            return Err(KzgError::NotOnCurveError(
                "commitment not on curve".to_owned(),
            ));
        }

        // Validate that all proofs are valid points on the G1 curve
        // Using parallel iterator for efficiency
        if proofs.iter().any(|proof| {
            proof == &G1Affine::identity()
                || !proof.is_on_curve()
                || !proof.is_in_correct_subgroup_assuming_on_curve()
        }) {
            return Err(KzgError::NotOnCurveError("proof not on curve".to_owned()));
        }

        // Compute evaluation challenges and evaluate polynomials at those points
        // This step:
        // 1. Generates random evaluation points for each blob
        // 2. Evaluates each blob's polynomial at its corresponding point
        let (evaluation_challenges, ys) =
            Self::compute_challenges_and_evaluate_polynomial(blobs, commitments, self.srs_order)?;

        // Convert each blob to its polynomial evaluation form and get the length of number of field elements
        // This length value is needed for computing the challenge
        let blobs_as_field_elements_length: Vec<u64> = blobs
            .iter()
            .map(|blob| blob.to_polynomial_eval_form().evaluations().len() as u64)
            .collect();

        // Perform the actual batch verification using the computed values:
        // - commitments: Original KZG commitments
        // - evaluation_challenges: Points where polynomials are evaluated
        // - ys: Values of polynomials at evaluation points
        // - proofs: KZG proofs for each evaluation
        // - blobs_as_field_elements_length: Length of each blob's polynomial
        self.verify_kzg_proof_batch(
            commitments,
            &evaluation_challenges,
            &ys,
            proofs,
            &blobs_as_field_elements_length,
        )
    }

    /// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_kzg_proof_batch
    /// A helper function to the `helpers::compute_powers` function. This does the below reference code from the 4844 spec.
    /// Ref: `# Append all inputs to the transcript before we hash
    ///      for commitment, z, y, proof in zip(commitments, zs, ys, proofs):
    ///          data += commitment + bls_field_to_bytes(z) + bls_field_to_bytes(y) + proof``
    fn compute_r_powers(
        &self,
        commitments: &[G1Affine],
        zs: &[Fr],
        ys: &[Fr],
        proofs: &[G1Affine],
        blobs_as_field_elements_length: &[u64],
    ) -> Result<Vec<Fr>, KzgError> {
        // Get the number of commitments/proofs we're processing
        let n = commitments.len();

        // Initial data length includes:
        // - 24 bytes for domain separator
        // - 8 bytes for number of field elements per blob
        // - 8 bytes for number of commitments
        let mut initial_data_length: usize = 40;

        // Calculate total input size:
        // - initial_data_length (40 bytes)
        // - For the number of commitments/zs/ys/proofs/blobs_as_field_elements_length (which are all the same length):
        //   * BYTES_PER_FIELD_ELEMENT for commitment
        //   * 2 * BYTES_PER_FIELD_ELEMENT for z and y values
        //   * BYTES_PER_FIELD_ELEMENT for proof
        //   * 8 bytes for blob length
        let input_size = initial_data_length
            + n * (BYTES_PER_FIELD_ELEMENT
                + 2 * BYTES_PER_FIELD_ELEMENT
                + BYTES_PER_FIELD_ELEMENT
                + 8);

        // Initialize buffer for data to be hashed
        let mut data_to_be_hashed: Vec<u8> = vec![0; input_size];

        // Copy domain separator to start of buffer
        // This provides domain separation for the hash function
        data_to_be_hashed[0..24].copy_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);

        // Convert number of commitments to bytes and copy to buffer
        // Uses configured endianness (Big or Little)
        // TODO(anupsv): To be removed and default to Big endian. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/27
        let n_bytes: [u8; 8] = match KZG_ENDIANNESS {
            Endianness::Big => n.to_be_bytes(),
            Endianness::Little => n.to_le_bytes(),
        };
        data_to_be_hashed[32..40].copy_from_slice(&n_bytes);

        let target_slice = &mut data_to_be_hashed[24..24 + (n * 8)];
        for (chunk, &length) in target_slice
            .chunks_mut(8)
            .zip(blobs_as_field_elements_length)
        {
            chunk.copy_from_slice(&length.to_be_bytes());
        }
        initial_data_length += n * 8;

        // Process each commitment, proof, and evaluation point/value
        for i in 0..n {
            // Serialize and copy commitment
            let mut v = vec![];

            // TODO(anupsv): Move serialization to helper function. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/32
            commitments[i].serialize_compressed(&mut v).map_err(|_| {
                KzgError::SerializationError("Failed to serialize commitment".to_string())
            })?;
            data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
                .copy_from_slice(&v[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;

            // Convert z point to bytes and copy
            let v = zs[i].into_bigint().to_bytes_be();
            data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
                .copy_from_slice(&v[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;

            // Convert y value to bytes and copy
            let v = ys[i].into_bigint().to_bytes_be();
            data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
                .copy_from_slice(&v[..]);
            initial_data_length += BYTES_PER_FIELD_ELEMENT;

            // Serialize and copy proof
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

        // Verify we filled the entire buffer
        // This ensures we didn't make any buffer overflow or underflow errors
        if initial_data_length != input_size {
            return Err(KzgError::InvalidInputLength);
        }

        // Hash all the data to get our random challenge
        let r = Self::hash_to_field_element(&data_to_be_hashed);

        // Compute powers of the random challenge: [r^0, r^1, r^2, ..., r^(n-1)]
        Ok(helpers::compute_powers(&r, n))
    }

    /// Verifies multiple KZG proofs efficiently.
    /// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_kzg_proof_batch
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
    ///
    fn verify_kzg_proof_batch(
        &self,
        commitments: &[G1Affine],
        zs: &[Fr],
        ys: &[Fr],
        proofs: &[G1Affine],
        blobs_as_field_elements_length: &[u64],
    ) -> Result<bool, KzgError> {
        // Verify that all input arrays have the same length
        // This is crucial for batch verification to work correctly
        if !(commitments.len() == zs.len() && zs.len() == ys.len() && ys.len() == proofs.len()) {
            return Err(KzgError::GenericError(
                "length's of the input are not the same".to_owned(),
            ));
        }

        // Check that all commitments are valid points on the G1 curve
        // This prevents invalid curve attacks
        if !commitments
            .iter()
            .all(|commitment| is_on_curve_g1(&G1Projective::from(*commitment)))
        {
            return Err(KzgError::NotOnCurveError(
                "commitment not on curve".to_owned(),
            ));
        }

        // Check that all proofs are valid points on the G1 curve
        if !proofs
            .iter()
            .all(|proof| is_on_curve_g1(&G1Projective::from(*proof)))
        {
            return Err(KzgError::NotOnCurveError("proof".to_owned()));
        }

        // Verify that the trusted setup point τ*G2 is on the G2 curve
        if !helpers::is_on_curve_g2(&G2Projective::from(*self.get_g2_tau()?)) {
            return Err(KzgError::NotOnCurveError("g2 tau".to_owned()));
        }

        let n = commitments.len();

        // Initialize vectors to store:
        // c_minus_y: [C_i - [y_i]]  (commitment minus the evaluation point encrypted)
        // r_times_z: [r^i * z_i]    (powers of random challenge times evaluation points)
        let mut c_minus_y: Vec<G1Affine> = Vec::with_capacity(n);
        let mut r_times_z: Vec<Fr> = Vec::with_capacity(n);

        // Compute powers of the random challenge: [r^0, r^1, r^2, ..., r^(n-1)]
        let r_powers =
            self.compute_r_powers(commitments, zs, ys, proofs, blobs_as_field_elements_length)?;

        // Compute Σ(r^i * proof_i)
        let proof_lincomb = helpers::g1_lincomb(proofs, &r_powers)?;

        // For each proof i:
        // 1. Compute C_i - [y_i]
        // 2. Compute r^i * z_i
        for i in 0..n {
            // Encrypt y_i as a point on G1
            let ys_encrypted = G1Affine::generator() * ys[i];
            // Compute C_i - [y_i] and convert to affine coordinates
            c_minus_y.push((commitments[i] - ys_encrypted).into_affine());
            // Compute r^i * z_i
            r_times_z.push(r_powers[i] * zs[i]);
        }

        // Compute:
        // proof_z_lincomb = Σ(r^i * z_i * proof_i)
        // c_minus_y_lincomb = Σ(r^i * (C_i - [y_i]))
        let proof_z_lincomb = helpers::g1_lincomb(proofs, &r_times_z)?;
        let c_minus_y_lincomb = helpers::g1_lincomb(&c_minus_y, &r_powers)?;

        // Compute right-hand side of the pairing equation
        let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

        // Verify the pairing equation:
        // e(Σ(r^i * proof_i), [τ]) = e(Σ(r^i * (C_i - [y_i])) + Σ(r^i * z_i * proof_i), [1])
        let result = Self::pairings_verify(
            proof_lincomb,
            *self.get_g2_tau()?,
            rhs_g1.into(),
            G2Affine::generator(),
        );
        Ok(result)
    }
}
