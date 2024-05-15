use std::{cmp, fs::File, io::{self, BufRead, BufReader, Cursor, Read}, sync::Arc};
use std::{borrow::BorrowMut, io::{Error, ErrorKind, Seek, SeekFrom}};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective, FrConfig};
use ark_ec::AffineRepr;
use ark_std::ops::{Mul, MulAssign, Div};
use ark_ff::{BigInt, BigInteger, BigInteger256, Field, MontBackend, PrimeField};
use num_bigint::{BigInt as NBigInt, Sign};
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use ark_serialize::{CanonicalDeserialize};
use ark_std::{str::FromStr, vec::Vec, One, Zero};
use sha2::digest::typenum::assert_type;
use ark_std::{UniformRand};

use crate::consts::{BYTES_PER_FIELD_ELEMENT, FIELD_ELEMENTS_PER_BLOB, SIZE_OF_G1_AFFINE_COMPRESSED};

const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();


pub fn str_to_limbs_u64(num: &str) -> (bool, Vec<u64>) {
    let (sign, digits) = NBigInt::from_str(num)
        .expect("could not parse to bigint")
        .to_radix_le(16);
    let limbs = digits
        .chunks(16)
        .map(|chunk| {
            let mut this = 0u64;
            for (i, hexit) in chunk.iter().enumerate() {
                this += (*hexit as u64) << (4 * i);
            }
            this
        })
        .collect::<Vec<_>>();

    let sign_is_positive = sign != Sign::Minus;
    (sign_is_positive, limbs)
}

pub fn read_in_poly(file_path: &str) -> io::Result<Vec<Fr>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut points: Vec<Fr> = vec![];
    let data: Vec<&str> = vec![
        "18509687166259998559431742400745213215303672178265145616189723246936371285950",
        "1042956860821271033764372023776706938868206325287280763408780726913284433168",
        "13903648613232639065682944596231864651183806329161496148385108045466894868727",
        "9399976246560875741400140630516934157310655905623936507606453180630354012129",
        "7979778874120980607349869992005327780887712966485752164610578992433710139337",
        "12774039773678037408637611172591150553935962864430685423696151625758272024838",
        "13278110700652338794964055701667882650389974356823325563897163845809618247764",
        "9195927021934526420626100076793311608643348380599791682755320330807580995220",
        "10109689849487236541262284005728937468335592817193417422238857891550393634909",
        "7984845141229659645823324591136846831313596115801722426167653744554136749195"
    ];

    for line_result in reader.lines() {
        let line = line_result?;  // Retrieve the line, handling potential I/O errors
        let trim_line = line.trim_end();

        // println!("{}", Fr::from(line.parse::<u64>().unwrap()));
        // let yy = Fr::new(BigInt::from(5_u64));
        let num = Fr::from_str(trim_line).expect("should be fine");
        // println!("{:?}", num.0);
        // println!("{:?}", str_to_limbs_u64(data[i]).1);
        points.push(num);
    }

    Ok(points)
}

/// Reads data from a file in chunks of a specified size.
pub fn read_in_g2_str(file_path: &str) -> io::Result<Vec<G2Projective>> {

    // Open the file for reading
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut points: Vec<G2Projective> = vec![];

    // Iterate over each line in the file
    for line_result in reader.lines() {
        let mut line = line_result?;  // Retrieve the line, handling potential I/O errors
        line = line.trim_end().to_string();

        
        // Split the line at each comma and process the parts
        let parts: Vec<&str> = line.split(',').collect();
        
        let x_a0 = Fq::from_str(parts[0]).expect("should be fine");
        let x_a1 = Fq::from_str(parts[1]).expect("should be fine");

        let y_a0 = Fq::from_str(parts[2]).expect("should be fine");
        let y_a1 = Fq::from_str(parts[3]).expect("should be fine");

        let x = Fq2::new(x_a0, x_a1);
        let y = Fq2::new(y_a0, y_a1);

        let point = G2Affine::new_unchecked(x, y);
        
        points.push(G2Projective::from(point));
    }

    Ok(points)
}

fn bytes_to_bn_field(the_bytes: &Vec<u8>) -> Fr {
    Fr::from_be_bytes_mod_order(the_bytes)
}

pub fn blob_to_polynomial(blob: &Vec<u8>) -> Vec<Fr>{
    // if blob.len() != BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB {
    //     panic!("blob supplied isn't of the right length");
    // }
    to_fr_array(&blob).unwrap()
}

fn serialize_poly(poly: Vec<Fr>) -> Vec<u8> {
	let mut blob: Vec<u8> = Vec::<u8>::with_capacity(BYTES_PER_FIELD_ELEMENT*FIELD_ELEMENTS_PER_BLOB);
	for i in 0..poly.len() {
		blob[i*BYTES_PER_FIELD_ELEMENT..(i+1)*BYTES_PER_FIELD_ELEMENT].copy_from_slice(&poly[i].into_bigint().to_bytes_be());
	}
	blob
}

/// Reads data from a file in chunks of a specified size.
pub fn read_in_g1_str(file_path: &str) -> io::Result<Vec<G1Projective>> {

    // Open the file for reading
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut points: Vec<G1Projective> = vec![];

    // Iterate over each line in the file
    for line_result in reader.lines() {
        let mut line = line_result?;  // Retrieve the line, handling potential I/O errors
        line = line.trim_end().to_string();

        
        // Split the line at each comma and process the parts
        let parts: Vec<&str> = line.split(',').collect();
        
        let x = Fq::from_str(parts[0]).expect("should be fine");
        let y = Fq::from_str(parts[1]).expect("should be fine");

        // println!("x -> {:?}", x.0);
        // println!("y -> {:?}", y.0);
        // println!(" ");

        let point = G1Affine::new_unchecked(x, y);
        
        points.push(G1Projective::from(point));
    }

    Ok(points)
}

/// Reads data from a file in chunks of a specified size.
pub fn read_in_g1(file_path: &str) -> io::Result<Vec<G1Projective>> {

    // Open the file for reading
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut points: Vec<G1Projective> = vec![];

    // Iterate over each line in the file
    for line_result in reader.lines() {
        let mut line = line_result?;  // Retrieve the line, handling potential I/O errors
        line = line.trim_end().to_string();

        
        // Split the line at each comma and process the parts
        let parts: Vec<&str> = line.split(',').collect();
        
        let x_u64 = parts[0].parse::<u64>().unwrap();
        let x = Fq::new(BigInt::from(x_u64));

        let y_u64 = parts[1].parse::<u64>().unwrap();
        let y = Fq::from(y_u64);
        let point = G1Affine::new_unchecked(x, y);
        
        points.push(G1Projective::from(point));
    }

    Ok(points)
}

/// Reads data from a file in chunks of a specified size.
pub fn read_in_g2(file_path: &str) -> io::Result<Vec<G2Projective>> {

    // Open the file for reading
    let file = File::open(file_path)?;
    let reader: BufReader<File> = BufReader::new(file);
    let mut points: Vec<G2Projective> = vec![];

    // Iterate over each line in the file
    for line_result in reader.lines() {
        let mut line = line_result?;  // Retrieve the line, handling potential I/O errors
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }

        let numbers: Vec<u64> = line.split(',')
                                    .filter_map(|s| s.trim().parse::<u64>().ok())
                                    .collect();

        
        let xa0_fq = Fq::from(numbers[0]);
        let xa1_fq = Fq::from(numbers[1]);
        let ya0_fq = Fq::from(numbers[2]);
        let ya1_fq = Fq::from(numbers[3]);

        // Create the Fq2 components
        let x = Fq2::new(xa0_fq, xa1_fq);
        let y = Fq2::new(ya0_fq, ya1_fq);

        let point = G2Affine::new_unchecked(x, y);
        points.push(G2Projective::from(point));
    }
    Ok(points)
}

fn convert_by_padding_empty_byte(data: &[u8]) -> Vec<u8> {
    let data_size = data.len();
    let parse_size = BYTES_PER_FIELD_ELEMENT - 1;
    let put_size = BYTES_PER_FIELD_ELEMENT;

    let data_len = (data_size + parse_size - 1) / parse_size;
    let mut valid_data = vec![0u8; data_len * put_size];
    let mut valid_end = valid_data.len();

    for i in 0..data_len {
        let start = i * parse_size;
        let mut end = (i + 1) * parse_size;
        if end > data_size {
            end = data_size;
            valid_end = end - start + 1 + i * put_size;
        }

        // Set the first byte of each chunk to 0
        valid_data[i * BYTES_PER_FIELD_ELEMENT] = 0x00;
        // Copy data from original to new vector, adjusting for the initial zero byte
        valid_data[i * BYTES_PER_FIELD_ELEMENT + 1..i * BYTES_PER_FIELD_ELEMENT + 1 + end - start]
            .copy_from_slice(&data[start..end]);
    }

    valid_data.truncate(valid_end);
    valid_data
}

fn remove_empty_byte_from_padded_bytes(data: &[u8]) -> Vec<u8> {
    let data_size = data.len();
    let parse_size = BYTES_PER_FIELD_ELEMENT;
    let data_len = (data_size + parse_size - 1) / parse_size;

    let put_size = BYTES_PER_FIELD_ELEMENT - 1;
    let mut valid_data = vec![0u8; data_len * put_size];
    let mut valid_len = valid_data.len();

    for i in 0..data_len {
        let start = i * parse_size + 1; // Skip the first byte which is the empty byte
        let mut end = (i + 1) * parse_size;
        
        if end > data_size {
            end = data_size;
            valid_len = i * put_size + end - start;
        }

        // Calculate the end of the slice in the output vector
        let output_end = i * put_size + end - start;
        valid_data[i * put_size..output_end].copy_from_slice(&data[start..end]);
    }

    valid_data.truncate(valid_len);
    valid_data
}

pub fn set_bytes_canonical_manual(data: &[u8]) -> Fr {
    let mut arrays: [u64; 4] = Default::default();  // Initialize an array of four [u8; 8] arrays

    for (i, chunk) in data.chunks(8).enumerate() {
        arrays[i] = u64::from_be_bytes(chunk.try_into().expect("Slice with incorrect length"));
    }
    arrays.reverse();
    Fr::from_bigint(BigInt::new(arrays)).unwrap()
}

pub fn set_bytes_canonical(data: &[u8]) -> Fr {
    return Fr::from_be_bytes_mod_order(&data);
}

fn get_num_element(data_len: usize, symbol_size: usize) -> usize {
    (data_len + symbol_size - 1) / symbol_size
}

fn to_fr_array(data: &[u8]) -> Result<Vec<Fr>, &'static str> {
    let num_ele = get_num_element(data.len(), BYTES_PER_FIELD_ELEMENT);
    let mut eles = vec![Fr::zero(); num_ele];  // Initialize with zero elements

    for i in 0..num_ele {
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;
        if end > data.len() {
            let mut padded = vec![0u8; BYTES_PER_FIELD_ELEMENT];
            padded[..data.len() - start].copy_from_slice(&data[start..]);
            eles[i] = set_bytes_canonical(&padded);
        } else {
            eles[i] = set_bytes_canonical(&data[start..end]);
        }
    }
    Ok(eles)
}

fn to_byte_array(data_fr: &[Fr], max_data_size: u64) -> Vec<u8> {
    let n = data_fr.len();
    let data_size = cmp::min(n * BYTES_PER_FIELD_ELEMENT, max_data_size as usize);
    let mut data = vec![0u8; data_size];

    for i in 0..n {
        let v: Vec<u8> = data_fr[i].into_bigint().to_bytes_be();
        // println!("{:?}", fr_element.into_bigint().to_bytes_be()); // how to convert rust number to .Bytes() in gnark

        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;

        if (end as u64) > max_data_size {
            let slice_end = cmp::min(v.len(), max_data_size as usize - start);
            data[start..start + slice_end].copy_from_slice(&v[..slice_end]);
            break;
        } else {
            let actual_end = cmp::min(end, data_size);
            data[start..actual_end].copy_from_slice(&v[..actual_end - start]);
        }
    }
    data
}

fn is_zeroed(first_byte: u8, buf: Vec<u8>) -> bool {
	if first_byte != 0 {
		return false
	}

    for i in 0..buf.len(){
        if buf[i] != 0 {
			return false
		}
    }
	true
}

pub fn str_vec_to_fr_vec(input: Vec<&str>) -> Vec<Fr>{

    let mut output: Vec<Fr> = Vec::<Fr>::with_capacity(input.len());

    for i in 0..input.len() {
        if input[i] == "-1" {
            let mut test = Fr::one();
            test.neg_in_place();
            output.push(test);
        } else {
            output.push(Fr::from_str(input[i]).expect("yes"));
        }
    }
    
    output
}

// needs work
pub fn read_g1_point_from_bytes_be(g1_bytes_be: &Vec<u8>) -> G1Affine{
    let mut m_mask: u8 = 0b11 << 6;
    let m_compressed_infinity: u8 = 0b01 << 6;
    let m_data = g1_bytes_be[0] & m_mask;

    if m_data == m_compressed_infinity {
		if !is_zeroed(g1_bytes_be[0] & !m_mask, g1_bytes_be[1..SIZE_OF_G1_AFFINE_COMPRESSED].to_vec()) {
			panic!("point at infinity not coded properly");
		}
		return G1Affine::zero();
	}
    
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(g1_bytes_be);
    let y_parity = (x_bytes[0] >> 7) != 0; // Extract parity bit

    x_bytes[0] &= !m_mask;
    x_bytes.reverse();
    let x = Fq::from_le_bytes_mod_order(&x_bytes);
    // Attempt to recover the full point from x and the parity of y
    let point = G1Affine::get_point_from_x_unchecked(x, y_parity)
        .unwrap();
    point
}

pub fn compute_quotient_eval_on_domain(z_fr: Fr, eval_fr: &Vec<Fr>, value_fr: Fr, roots_of_unities: &Vec<Fr>) -> Fr {

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


// Loads data from files. This data was generated by gnark and is DA compatible.
// Tests deserialization of data and equivalence.
#[test]
fn test_blob_to_polynomial(){

    let file = File::open("/Users/asv/projects/rust-kzg-bn254/src/test-files/blobs.txt").unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; 32];
    let mut read_fr_from_bytes: Vec<Fr> = vec![];
    let mut fr_from_str_vec: Vec<Fr> = vec![];

    // Loop to read the file 32 bytes at a time
    loop {
        match reader.read(&mut buffer[..]) {
            Ok(0) => {
                // No more data to read
                break;
            }
            Ok(n) => {
                // Process the chunk of data just read
                read_fr_from_bytes.push(Fr::from_be_bytes_mod_order(&buffer[..n]))
            }
            Err(e) => panic!("{}", e),
        }
    }
    

    let file2 = File::open("/Users/asv/projects/rust-kzg-bn254/src/test-files/blobs-from-fr.txt").unwrap();
    let reader2 = BufReader::new(file2);
    for (i, line) in reader2.lines().enumerate() {
        let line = line.unwrap();
        let trimmed_line = line.trim_end(); // Trim whitespace from the end
        let the_strings_str: Vec<&str> = trimmed_line.split(',').collect(); // Split the line on commas
        let fr_from_str = Fr::from_str(the_strings_str[0]).expect("should be fine");
        fr_from_str_vec.push(fr_from_str);
        assert_eq!(fr_from_str, read_fr_from_bytes[i]);
    }

    let mut file3 = File::open("/Users/asv/projects/rust-kzg-bn254/src/test-files/blobs.txt").unwrap();
    let mut contents = Vec::new();
    file3.read_to_end(&mut contents).unwrap();


    assert_eq!(fr_from_str_vec, blob_to_polynomial(&contents));
    

}

#[test]
fn test_compute_quotient_eval_on_domain(){
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
    let roots_of_unities: Vec<Fr> = str_vec_to_fr_vec(roots_of_unities_raw);
    for i in 0..eval_raw.len() {
        eval_fr.push(Fr::from_str(eval_raw[i]).expect("yes"));
    }

    let result = compute_quotient_eval_on_domain(z_fr, &eval_fr, value_fr, &roots_of_unities);
    let confirmed_result = Fr::from_str("20008798420615294489302706738008175134837093401197634135729610787152508035605").expect("yes");

    assert_eq!(confirmed_result, result);

}

#[test]
fn test_reading_G1_from_gnark_serialization(){

    // points have to be compressed
    // input should be in be order, exactly how gnark gives it.

    let file = File::open("/Users/asv/projects/rust-kzg-bn254/src/test-files/g1.serialize.input.bytes").unwrap();
    let reader = BufReader::new(file);
    let file2 = File::open("/Users/asv/projects/rust-kzg-bn254/src/test-files/g1.serialize.input.strings").unwrap();
    let reader2 = BufReader::new(file2);

    let mut g1_from_bytes: Vec<G1Affine> = vec![];
    let mut g1_from_strings: Vec<G1Affine> = vec![];

    // Read lines from the file
    for line in reader.lines() {
        let line = line.unwrap();
        let trimmed_line = line.trim_end(); // Trim whitespace from the end
        let the_bytes_str: Vec<&str> = trimmed_line.split(',').collect(); // Split the line on commas
        let the_bytes: Vec<u8> = the_bytes_str.iter().map(|each| u8::from_str(each).unwrap()).collect();
        g1_from_bytes.push(read_g1_point_from_bytes_be(&the_bytes));
    }

    for line in reader2.lines() {
        let line = line.unwrap();
        let trimmed_line = line.trim_end(); // Trim whitespace from the end
        let the_strings_str: Vec<&str> = trimmed_line.split(',').collect(); // Split the line on commas
        let hard_coded_x = Fq::from_str(the_strings_str[0]).expect("should be fine");
        let hard_coded_y = Fq::from_str(the_strings_str[1]).expect("should be fine");
        let hard_coded = G1Affine::new(hard_coded_x, hard_coded_y);
        g1_from_strings.push(hard_coded);
    }

    assert_eq!(g1_from_bytes[1], g1_from_strings[1]);
    // let mut G1_bytes: Vec<u8> = vec![229, 21, 50, 140, 127, 83, 94, 189, 76, 233, 206, 36, 182, 167, 103, 177, 85, 78, 128, 213, 105, 250, 115, 253, 137, 218, 25, 229, 173, 160, 95, 243];
    // let point = read_g1_point_from_bytes_be(&G1_bytes);

    // let hard_coded_x = Fq::from_str("16773028061060032871918660906320577102855620654794472948347825705218411094003").expect("should be fine");
    // let hard_coded_y = Fq::from_str("12737475397041020205822931299654699413635626329200816516563572631086356908955").expect("should be fine");
    // let hard_coded = G1Affine::new(hard_coded_x, hard_coded_y);
    // assert_eq!(hard_coded.x(), point.x());
    // assert_eq!(hard_coded.y(), point.y());
    // assert_eq!(hard_coded.is_in_correct_subgroup_assuming_on_curve(), point.is_in_correct_subgroup_assuming_on_curve());
    // assert_eq!(hard_coded.is_on_curve(), point.is_on_curve());
    // assert!(hard_coded.is_on_curve());
}

#[test]
fn test_to_fr_array(){
    let converted = convert_by_padding_empty_byte(vec![42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27, 116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40].as_slice());
    let data_fr = to_fr_array(&converted).unwrap();
    let result = to_byte_array(&data_fr, converted.len().try_into().unwrap());
    assert_eq!(converted, result, "should be deserialized properly");

    let ga_converted = convert_by_padding_empty_byte(GETTYSBURG_ADDRESS_BYTES);
    let ga_converted_fr = to_fr_array(&ga_converted).unwrap();
    assert_eq!(to_byte_array(&ga_converted_fr, ga_converted.len().try_into().unwrap()), ga_converted);

}

#[test]
fn test_how_to_read_bytes(){
    let the_bytes = vec![31, 94, 220, 111, 30, 251, 22, 93, 69, 166, 84, 121, 141, 75, 170, 165, 14, 59, 77, 36, 24, 41, 19, 174, 245, 17, 10, 21, 88, 14, 186, 173];
    let data = Fr::from_be_bytes_mod_order(&the_bytes);
    println!("{:?}", data.0);
}

#[test]
fn test_get_num_element(){
    let num_elements = get_num_element(1000, BYTES_PER_FIELD_ELEMENT);
    assert_eq!(num_elements, 32_usize, "needs to be equal");
}

#[test]
fn test_set_canonical_bytes(){
    let data: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
    let fr_element = set_bytes_canonical_manual(&data);
    // println!("{:?}", fr_element.0);
    // println!("{:?}", Fr::from_be_bytes_mod_order(&data).0);
    assert_eq!(fr_element, set_bytes_canonical(&data), "needs to be equal");
}

#[test]
fn test_convert_by_padding_empty_byte(){
    
    let mut padded_data = convert_by_padding_empty_byte("hi".as_bytes());
    assert_eq!(padded_data, vec![0, 104, 105], "testing adding padding");

    let mut unpadded_data = remove_empty_byte_from_padded_bytes(&padded_data);
    assert_eq!(unpadded_data, vec![104, 105], "testing removing padding");

    let long_string = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();
    let result: Vec<u8> = vec![0, 70, 111, 117, 114, 115, 99, 111, 114, 101, 32, 97, 110, 100, 32, 115, 101, 118, 101, 110, 32, 121, 101, 97, 114, 115, 32, 97, 103, 111, 32, 111, 0, 117, 114, 32, 102, 97, 116, 104, 101, 114, 115, 32, 98, 114, 111, 117, 103, 104, 116, 32, 102, 111, 114, 116, 104, 44, 32, 111, 110, 32, 116, 104, 0, 105, 115, 32, 99, 111, 110, 116, 105, 110, 101, 110, 116, 44, 32, 97, 32, 110, 101, 119, 32, 110, 97, 116, 105, 111, 110, 44, 32, 99, 111, 110, 0, 99, 101, 105, 118, 101, 100, 32, 105, 110, 32, 108, 105, 98, 101, 114, 116, 121, 44, 32, 97, 110, 100, 32, 100, 101, 100, 105, 99, 97, 116, 101, 0, 100, 32, 116, 111, 32, 116, 104, 101, 32, 112, 114, 111, 112, 111, 115, 105, 116, 105, 111, 110, 32, 116, 104, 97, 116, 32, 97, 108, 108, 32, 109, 0, 101, 110, 32, 97, 114, 101, 32, 99, 114, 101, 97, 116, 101, 100, 32, 101, 113, 117, 97, 108, 46, 32, 78, 111, 119, 32, 119, 101, 32, 97, 114, 0, 101, 32, 101, 110, 103, 97, 103, 101, 100, 32, 105, 110, 32, 97, 32, 103, 114, 101, 97, 116, 32, 99, 105, 118, 105, 108, 32, 119, 97, 114, 44, 0, 32, 116, 101, 115, 116, 105, 110, 103, 32, 119, 104, 101, 116, 104, 101, 114, 32, 116, 104, 97, 116, 32, 110, 97, 116, 105, 111, 110, 44, 32, 111, 0, 114, 32, 97, 110, 121, 32, 110, 97, 116, 105, 111, 110, 32, 115, 111, 32, 99, 111, 110, 99, 101, 105, 118, 101, 100, 44, 32, 97, 110, 100, 32, 0, 115, 111, 32, 100, 101, 100, 105, 99, 97, 116, 101, 100, 44, 32, 99, 97, 110, 32, 108, 111, 110, 103, 32, 101, 110, 100, 117, 114, 101, 46, 32, 0, 87, 101, 32, 97, 114, 101, 32, 109, 101, 116, 32, 111, 110, 32, 97, 32, 103, 114, 101, 97, 116, 32, 98, 97, 116, 116, 108, 101, 45, 102, 105, 0, 101, 108, 100, 32, 111, 102, 32, 116, 104, 97, 116, 32, 119, 97, 114, 46, 32, 87, 101, 32, 104, 97, 118, 101, 32, 99, 111, 109, 101, 32, 116, 0, 111, 32, 100, 101, 100, 105, 99, 97, 116, 101, 32, 97, 32, 112, 111, 114, 116, 105, 111, 110, 32, 111, 102, 32, 116, 104, 97, 116, 32, 102, 105, 0, 101, 108, 100, 44, 32, 97, 115, 32, 97, 32, 102, 105, 110, 97, 108, 32, 114, 101, 115, 116, 105, 110, 103, 45, 112, 108, 97, 99, 101, 32, 102, 0, 111, 114, 32, 116, 104, 111, 115, 101, 32, 119, 104, 111, 32, 104, 101, 114, 101, 32, 103, 97, 118, 101, 32, 116, 104, 101, 105, 114, 32, 108, 105, 0, 118, 101, 115, 44, 32, 116, 104, 97, 116, 32, 116, 104, 97, 116, 32, 110, 97, 116, 105, 111, 110, 32, 109, 105, 103, 104, 116, 32, 108, 105, 118, 0, 101, 46, 32, 73, 116, 32, 105, 115, 32, 97, 108, 116, 111, 103, 101, 116, 104, 101, 114, 32, 102, 105, 116, 116, 105, 110, 103, 32, 97, 110, 100, 0, 32, 112, 114, 111, 112, 101, 114, 32, 116, 104, 97, 116, 32, 119, 101, 32, 115, 104, 111, 117, 108, 100, 32, 100, 111, 32, 116, 104, 105, 115, 46, 0, 32, 66, 117, 116, 44, 32, 105, 110, 32, 97, 32, 108, 97, 114, 103, 101, 114, 32, 115, 101, 110, 115, 101, 44, 32, 119, 101, 32, 99, 97, 110, 0, 110, 111, 116, 32, 100, 101, 100, 105, 99, 97, 116, 101, 44, 32, 119, 101, 32, 99, 97, 110, 110, 111, 116, 32, 99, 111, 110, 115, 101, 99, 114, 0, 97, 116, 101, 226, 128, 148, 119, 101, 32, 99, 97, 110, 110, 111, 116, 32, 104, 97, 108, 108, 111, 119, 226, 128, 148, 116, 104, 105, 115, 32, 103, 0, 114, 111, 117, 110, 100, 46, 32, 84, 104, 101, 32, 98, 114, 97, 118, 101, 32, 109, 101, 110, 44, 32, 108, 105, 118, 105, 110, 103, 32, 97, 110, 0, 100, 32, 100, 101, 97, 100, 44, 32, 119, 104, 111, 32, 115, 116, 114, 117, 103, 103, 108, 101, 100, 32, 104, 101, 114, 101, 44, 32, 104, 97, 118, 0, 101, 32, 99, 111, 110, 115, 101, 99, 114, 97, 116, 101, 100, 32, 105, 116, 32, 102, 97, 114, 32, 97, 98, 111, 118, 101, 32, 111, 117, 114, 32, 0, 112, 111, 111, 114, 32, 112, 111, 119, 101, 114, 32, 116, 111, 32, 97, 100, 100, 32, 111, 114, 32, 100, 101, 116, 114, 97, 99, 116, 46, 32, 84, 0, 104, 101, 32, 119, 111, 114, 108, 100, 32, 119, 105, 108, 108, 32, 108, 105, 116, 116, 108, 101, 32, 110, 111, 116, 101, 44, 32, 110, 111, 114, 32, 0, 108, 111, 110, 103, 32, 114, 101, 109, 101, 109, 98, 101, 114, 32, 119, 104, 97, 116, 32, 119, 101, 32, 115, 97, 121, 32, 104, 101, 114, 101, 44, 0, 32, 98, 117, 116, 32, 105, 116, 32, 99, 97, 110, 32, 110, 101, 118, 101, 114, 32, 102, 111, 114, 103, 101, 116, 32, 119, 104, 97, 116, 32, 116, 0, 104, 101, 121, 32, 100, 105, 100, 32, 104, 101, 114, 101, 46, 32, 73, 116, 32, 105, 115, 32, 102, 111, 114, 32, 117, 115, 32, 116, 104, 101, 32, 0, 108, 105, 118, 105, 110, 103, 44, 32, 114, 97, 116, 104, 101, 114, 44, 32, 116, 111, 32, 98, 101, 32, 100, 101, 100, 105, 99, 97, 116, 101, 100, 0, 32, 104, 101, 114, 101, 32, 116, 111, 32, 116, 104, 101, 32, 117, 110, 102, 105, 110, 105, 115, 104, 101, 100, 32, 119, 111, 114, 107, 32, 119, 104, 0, 105, 99, 104, 32, 116, 104, 101, 121, 32, 119, 104, 111, 32, 102, 111, 117, 103, 104, 116, 32, 104, 101, 114, 101, 32, 104, 97, 118, 101, 32, 116, 0, 104, 117, 115, 32, 102, 97, 114, 32, 115, 111, 32, 110, 111, 98, 108, 121, 32, 97, 100, 118, 97, 110, 99, 101, 100, 46, 32, 73, 116, 32, 105, 0, 115, 32, 114, 97, 116, 104, 101, 114, 32, 102, 111, 114, 32, 117, 115, 32, 116, 111, 32, 98, 101, 32, 104, 101, 114, 101, 32, 100, 101, 100, 105, 0, 99, 97, 116, 101, 100, 32, 116, 111, 32, 116, 104, 101, 32, 103, 114, 101, 97, 116, 32, 116, 97, 115, 107, 32, 114, 101, 109, 97, 105, 110, 105, 0, 110, 103, 32, 98, 101, 102, 111, 114, 101, 32, 117, 115, 226, 128, 148, 116, 104, 97, 116, 32, 102, 114, 111, 109, 32, 116, 104, 101, 115, 101, 32, 0, 104, 111, 110, 111, 114, 101, 100, 32, 100, 101, 97, 100, 32, 119, 101, 32, 116, 97, 107, 101, 32, 105, 110, 99, 114, 101, 97, 115, 101, 100, 32, 0, 100, 101, 118, 111, 116, 105, 111, 110, 32, 116, 111, 32, 116, 104, 97, 116, 32, 99, 97, 117, 115, 101, 32, 102, 111, 114, 32, 119, 104, 105, 99, 0, 104, 32, 116, 104, 101, 121, 32, 104, 101, 114, 101, 32, 103, 97, 118, 101, 32, 116, 104, 101, 32, 108, 97, 115, 116, 32, 102, 117, 108, 108, 32, 0, 109, 101, 97, 115, 117, 114, 101, 32, 111, 102, 32, 100, 101, 118, 111, 116, 105, 111, 110, 226, 128, 148, 116, 104, 97, 116, 32, 119, 101, 32, 104, 0, 101, 114, 101, 32, 104, 105, 103, 104, 108, 121, 32, 114, 101, 115, 111, 108, 118, 101, 32, 116, 104, 97, 116, 32, 116, 104, 101, 115, 101, 32, 100, 0, 101, 97, 100, 32, 115, 104, 97, 108, 108, 32, 110, 111, 116, 32, 104, 97, 118, 101, 32, 100, 105, 101, 100, 32, 105, 110, 32, 118, 97, 105, 110, 0, 226, 128, 148, 116, 104, 97, 116, 32, 116, 104, 105, 115, 32, 110, 97, 116, 105, 111, 110, 44, 32, 117, 110, 100, 101, 114, 32, 71, 111, 100, 44, 0, 32, 115, 104, 97, 108, 108, 32, 104, 97, 118, 101, 32, 97, 32, 110, 101, 119, 32, 98, 105, 114, 116, 104, 32, 111, 102, 32, 102, 114, 101, 101, 0, 100, 111, 109, 44, 32, 97, 110, 100, 32, 116, 104, 97, 116, 32, 103, 111, 118, 101, 114, 110, 109, 101, 110, 116, 32, 111, 102, 32, 116, 104, 101, 0, 32, 112, 101, 111, 112, 108, 101, 44, 32, 98, 121, 32, 116, 104, 101, 32, 112, 101, 111, 112, 108, 101, 44, 32, 102, 111, 114, 32, 116, 104, 101, 0, 32, 112, 101, 111, 112, 108, 101, 44, 32, 115, 104, 97, 108, 108, 32, 110, 111, 116, 32, 112, 101, 114, 105, 115, 104, 32, 102, 114, 111, 109, 32, 0, 116, 104, 101, 32, 101, 97, 114, 116, 104, 46];
    
    padded_data = convert_by_padding_empty_byte(long_string);
    assert_eq!(padded_data, result, "testing adding padding");

    unpadded_data = remove_empty_byte_from_padded_bytes(&padded_data);

    assert_eq!(unpadded_data, long_string, "testing adding padding");

}
