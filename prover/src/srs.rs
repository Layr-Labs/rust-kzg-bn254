use ark_bn254::G1Affine;
use crossbeam_channel::{bounded, Receiver};
use rust_kzg_bn254_primitives::errors::KzgError;
use rust_kzg_bn254_primitives::traits::ReadPointFromBytes;
use std::fs::File;
use std::io::{self, BufReader, Read};

/// Represents the Structured Reference String (SRS) used in KZG commitments.
#[derive(Debug, PartialEq, Clone)]
pub struct SRS {
    // SRS points are stored in monomial form, ready to be used for commitments with polynomials
    // in coefficient form. To commit against a polynomial in evaluation form, we need to transform
    // the SRS points to lagrange form using IFFT.
    pub g1: Vec<G1Affine>,
    /// The order of the SRS.
    pub order: u32,
}

impl SRS {
    /// Initializes the SRS by loading G1 points from a file.
    ///
    /// # Arguments
    ///
    /// * `path_to_g1_points` - The file path to load G1 points from.
    /// * `order` - The total order of the SRS.
    /// * `points_to_load` - The number of SRS points to load.
    ///
    /// # Returns
    ///
    /// * `Result<SRS, KzgError>` - The initialized SRS or an error.
    pub fn new(path_to_g1_points: &str, order: u32, points_to_load: u32) -> Result<Self, KzgError> {
        if points_to_load > order {
            return Err(KzgError::GenericError(
                "Number of points to load exceeds SRS order.".to_string(),
            ));
        }

        let g1_points =
            Self::parallel_read_g1_points(path_to_g1_points.to_owned(), points_to_load, false)?;

        Ok(Self {
            g1: g1_points,
            order,
        })
    }

    pub fn process_chunks<T>(receiver: Receiver<(Vec<u8>, usize, bool)>) -> Vec<(T, usize)>
    where
        T: ReadPointFromBytes,
    {
        // TODO: should we use rayon to process this in parallel?
        receiver
            .iter()
            .map(|(chunk, position, is_native)| {
                let point: T = if is_native {
                    T::read_point_from_bytes_native_compressed(&chunk)
                        .expect("Failed to read point from bytes")
                } else {
                    T::read_point_from_bytes_be(&chunk).expect("Failed to read point from bytes")
                };
                (point, position)
            })
            .collect()
    }

    /// Reads G1 points in parallel from a file.
    ///
    /// # Arguments
    ///
    /// * `file_path` - The path to the file containing G1 points.
    /// * `points_to_load` - The number of points to load.
    /// * `is_native` - Whether the points are in native Arkworks format.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<G1Affine>, KzgError>` - The loaded G1 points or an error.
    fn parallel_read_g1_points(
        file_path: String,
        points_to_load: u32,
        is_native: bool,
    ) -> Result<Vec<G1Affine>, KzgError> {
        let (sender, receiver) = bounded::<(Vec<u8>, usize, bool)>(1000);

        // Spawn the reader thread
        let reader_handle = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 32, points_to_load, is_native)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            },
        );

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers)
            .map(|_| {
                let receiver = receiver.clone();
                std::thread::spawn(move || Self::process_chunks::<G1Affine>(receiver))
            })
            .collect();

        // Wait for the reader thread to finish
        match reader_handle.join() {
            Ok(result) => match result {
                Ok(_) => {},
                Err(e) => return Err(KzgError::GenericError(e.to_string())),
            },
            Err(_) => {
                return Err(KzgError::GenericError(
                    "Reader thread panicked.".to_string(),
                ))
            },
        }

        // Collect and sort the results
        let mut all_points = Vec::new();
        for worker in workers {
            let points = worker.join().expect("Worker thread panicked.");
            all_points.extend(points);
        }

        // Sort by original position to maintain order
        all_points.sort_by_key(|&(_, position)| position);

        if all_points.len() != points_to_load as usize {
            return Err(KzgError::GenericError(format!(
                "Expected {} points, but got {}.",
                points_to_load,
                all_points.len()
            )));
        }

        // Extract the G1Affine points
        Ok(all_points.iter().map(|(point, _)| *point).collect())
    }

    /// Reads file chunks and sends them through a channel.
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file.
    /// * `sender` - Channel sender to send read chunks.
    /// * `point_size` - Size of each point in bytes.
    /// * `num_points` - Number of points to read.
    /// * `is_native` - Whether the points are in native format.
    ///
    /// # Returns
    ///
    /// * `io::Result<()>` - Ok if successful, or an I/O error.
    ///    TODO: chunks seems misleading here, since we read one field element at a time.
    fn read_file_chunks(
        file_path: &str,
        sender: crossbeam_channel::Sender<(Vec<u8>, usize, bool)>,
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

    /// read G1 points in parallel, by creating one reader thread, which reads
    /// bytes from the file, and fans them out to worker threads (one per
    /// cpu) which parse the bytes into G1Affine points. The worker threads
    /// then fan in the parsed points to the main thread, which sorts them by
    /// their original position in the file to maintain order. Not used anywhere
    /// but kept as a reference.
    ///
    /// # Arguments
    /// * `file_path` - The path to the file containing the G1 points
    /// * `points_to_load` - The number of points to load from the file
    /// * `is_native` - Whether the points are in native arkworks format or not
    ///
    /// # Returns
    /// * `Ok(Vec<G1Affine>)` - The G1 points read from the file
    /// * `Err(KzgError)` - An error occurred while reading the file
    pub fn parallel_read_g1_points_native(
        file_path: String,
        points_to_load: u32,
        is_native: bool,
    ) -> Result<Vec<G1Affine>, KzgError> {
        // Channel contains (bytes, position, is_native) tuples. The position is used to
        // reorder the points after processing them.
        let (sender, receiver) = bounded::<(Vec<u8>, usize, bool)>(1000);

        // Spawning the reader thread
        let reader_thread = std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Self::read_file_chunks(&file_path, sender, 32, points_to_load, is_native)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            },
        );

        let num_workers = num_cpus::get();

        let workers: Vec<_> = (0..num_workers)
            .map(|_| {
                let receiver = receiver.clone();
                std::thread::spawn(move || Self::process_chunks::<G1Affine>(receiver))
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
}
