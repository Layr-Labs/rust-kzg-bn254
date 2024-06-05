use crate::{
    blob::Blob,
    consts::BYTES_PER_FIELD_ELEMENT,
    errors::KzgError,
    helpers,
    polynomial::{Polynomial, PolynomialFormat},
    traits::ReadPointFromBytes,
};
use ark_bn254::{g1::G1Affine, Bn254, Fr, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::Read;
use ark_std::{ops::Div, str::FromStr, One, Zero};
use crossbeam_channel::{bounded, Sender};
use num_traits::ToPrimitive;
use std::{fs::File, io, io::BufReader};

#[derive(Debug, PartialEq, Clone)]
pub struct Kzg {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    params: Params,
    srs_order: u64,
    expanded_roots_of_unity: Vec<Fr>,
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
    ) -> Result<Self, KzgError> {
        if srs_points_to_load > srs_order {
            return Err(KzgError::GenericError(
                "number of points to load is more than the srs order".to_string(),
            ));
        }

        let g1_points =
            Self::parallel_read_g1_points(path_to_g1_points.to_owned(), srs_points_to_load)
                .map_err(|e| KzgError::SerializationError(e.to_string()))?;

        let g2_points_result: Result<Vec<G2Affine>, KzgError> =
            match (path_to_g2_points.is_empty(), g2_power_of2_path.is_empty()) {
                (false, _) => {
                    Self::parallel_read_g2_points(path_to_g2_points.to_owned(), srs_points_to_load)
                        .map_err(|e| KzgError::SerializationError(e.to_string()))
                },
                (_, false) => Self::read_g2_point_on_power_of_2(g2_power_of2_path),
                (true, true) => {
                    return Err(KzgError::GenericError(
                        "both g2 point files are empty, need the proper file specified".to_string(),
                    ))
                },
            };

        let g2_points = g2_points_result?;

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
        let log2_of_evals = length_of_data_after_padding
            .div_ceil(32)
            .next_power_of_two()
            .to_f64()
            .unwrap()
            .log2()
            .to_u8()
            .unwrap();
        self.params.max_fft_width = 1_u64 << log2_of_evals;

        if length_of_data_after_padding
            .div_ceil(BYTES_PER_FIELD_ELEMENT.try_into().unwrap())
            .next_power_of_two()
            >= self.srs_order
        {
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

        self.params.completed_setup = true;
        self.expanded_roots_of_unity = expanded_roots_of_unity;

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
    fn read_file_chunks(
        file_path: &str,
        sender: Sender<(Vec<u8>, usize)>,
        point_size: usize,
        num_points: u32,
    ) -> io::Result<()> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut position = 0;
        let mut buffer = vec![0u8; point_size];

        let mut i = 0;
        while let Ok(bytes_read) = reader.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }
            sender
                .send((buffer[..bytes_read].to_vec(), position))
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
    ) -> Result<Vec<G2Affine>, KzgError> {
        let (sender, receiver) = bounded::<(Vec<u8>, usize)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 64, srs_points_to_load)
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

    /// read G1 points in parallel
    pub fn parallel_read_g1_points(
        file_path: String,
        srs_points_to_load: u32,
    ) -> Result<Vec<G1Affine>, KzgError> {
        let (sender, receiver) = bounded::<(Vec<u8>, usize)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 32, srs_points_to_load)
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

    /// obtain copy of g2 points
    pub fn get_g2_points(&self) -> Vec<G2Affine> {
        self.g2.to_vec()
    }

    /// commit the actual polynomial with the values setup
    pub fn commit(&self, polynomial: &Polynomial) -> Result<G1Affine, KzgError> {
        if polynomial.len() > self.g1.len() {
            return Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string(),
            ));
        }

        // Configure multi-threading
        let config = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .build()
            .map_err(|err| KzgError::CommitError(err.to_string()))?;

        config.install(|| {
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
        })
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
        self.compute_kzg_proof(polynomial, index, &self.expanded_roots_of_unity)
    }

    /// function to compute the kzg proof given the values.
    pub fn compute_kzg_proof(
        &self,
        polynomial: &Polynomial,
        index: u64,
        root_of_unities: &[Fr],
    ) -> Result<G1Affine, KzgError> {
        if !self.params.completed_setup {
            return Err(KzgError::GenericError(
                "setup is not complete, run the data_setup functions".to_string(),
            ));
        }

        if polynomial.len() != root_of_unities.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }

        let eval_fr = polynomial.to_vec();
        let mut poly_shift: Vec<Fr> = Vec::with_capacity(eval_fr.len());
        let usized_index = if let Some(x) = index.to_usize() {
            x
        } else {
            return Err(KzgError::SerializationError(
                "index couldn't be converted to usize".to_string(),
            ));
        };

        let value_fr = eval_fr[usized_index];
        let z_fr = root_of_unities[usized_index];

        for fr in &eval_fr {
            poly_shift.push(*fr - value_fr);
        }

        let mut denom_poly = Vec::<Fr>::with_capacity(root_of_unities.len());
        for root_of_unity in root_of_unities.iter().take(eval_fr.len()) {
            denom_poly.push(*root_of_unity - z_fr);
        }

        let mut quotient_poly = Vec::<Fr>::with_capacity(root_of_unities.len());

        for i in 0..root_of_unities.len() {
            if denom_poly[i].is_zero() {
                quotient_poly.push(self.compute_quotient_eval_on_domain(
                    z_fr,
                    &eval_fr,
                    value_fr,
                    root_of_unities,
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

    /// refer to DA for more context
    pub fn compute_quotient_eval_on_domain(
        &self,
        z_fr: Fr,
        eval_fr: &[Fr],
        value_fr: Fr,
        roots_of_unities: &[Fr],
    ) -> Fr {
        let mut quotient = Fr::zero();
        let mut fi: Fr = Fr::zero();
        let mut numerator: Fr = Fr::zero();
        let mut denominator: Fr = Fr::zero();
        let mut temp: Fr = Fr::zero();

        roots_of_unities
            .iter()
            .enumerate()
            .for_each(|(i, omega_i)| {
                if *omega_i == z_fr {
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
            return Err(KzgError::FftError(
                "length provided is not a power of 2".to_string(),
            ));
        }

        let points_projective: Vec<G1Projective> = self.g1[..length]
            .iter()
            .map(|&p| G1Projective::from(p))
            .collect();

        match GeneralEvaluationDomain::<Fr>::new(length) {
            Some(domain) => {
                let ifft_result = domain.ifft(&points_projective);
                let ifft_result_affine: Vec<_> =
                    ifft_result.iter().map(|p| p.into_affine()).collect();
                Ok(ifft_result_affine)
            },
            None => Err(KzgError::FftError(
                "Could not perform IFFT due to domain consturction error".to_string(),
            )),
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

    fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
        let neg_b1 = -b1;
        let p = [a1, neg_b1];
        let q = [a2, b2];
        let result = Bn254::multi_pairing(p, q);
        result.is_zero()
    }
}
