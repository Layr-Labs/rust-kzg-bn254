#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
    use ark_ff::UniformRand;
    use lazy_static::lazy_static;
    use rand::Rng;
    use rust_kzg_bn254::{
        blob::Blob,
        errors::KzgError,
        helpers,
        kzg::KZG,
        polynomial::PolynomialCoeffForm,
    };
    use std::{env, fs::File, io::BufReader};
    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();
    use ark_std::{str::FromStr, One};

    // Function to determine the setup based on an environment variable
    fn determine_setup() -> KZG {
        match env::var("KZG_ENV") {
            Ok(val) if val == "mainnet-data" => KZG::setup(
                "tests/test-files/mainnet-data/g1.131072.point",
                "",
                "tests/test-files/mainnet-data/g2.point.powerOf2",
                268435456,
                131072,
            )
            .unwrap(),
            _ => KZG::setup(
                "tests/test-files/g1.point",
                "tests/test-files/g2.point",
                "tests/test-files/g2.point.powerOf2",
                3000,
                3000,
            )
            .unwrap(),
        }
    }

    // Define a static variable for setup
    lazy_static! {
        static ref KZG_INSTANCE: KZG = determine_setup();
        static ref KZG_3000: KZG = KZG::setup(
            "tests/test-files/g1.point",
            "tests/test-files/g2.point",
            "tests/test-files/g2.point.powerOf2",
            3000,
            3000,
        )
        .unwrap();
    }

    #[test]
    fn test_commit_errors() {
        let mut coeffs = vec![];
        for _ in 0..4000 {
            coeffs.push(Fr::one());
        }

        let polynomial = PolynomialCoeffForm::new(coeffs);
        let result = KZG_3000.commit_coeff_form(&polynomial);
        assert_eq!(
            result,
            Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string()
            ))
        );
    }

    #[test]
    fn test_kzg_setup_errors() {
        let kzg1 = KZG::setup("tests/test-files/g1.point", "", "", 3000, 3000);
        assert_eq!(
            kzg1,
            Err(KzgError::GenericError(
                "both g2 point files are empty, need the proper file specified".to_string()
            ))
        );

        let mut kzg2 = KZG::setup(
            "tests/test-files/g1.point",
            "tests/test-files/g2.point",
            "tests/test-files/g2.point.powerOf2",
            2,
            2,
        )
        .unwrap();

        let result = kzg2.data_setup_mins(4, 4);
        assert_eq!(
            result,
            Err(KzgError::SerializationError(
                "the supplied encoding parameters are not valid with respect to the SRS."
                    .to_string()
            ))
        );

        let kzg3 = KZG::setup(
            "tests/test-files/g1.point",
            "tests/test-files/g2.point",
            "tests/test-files/g2.point.powerOf2",
            3000,
            3001,
        );
        assert_eq!(
            kzg3,
            Err(KzgError::GenericError(
                "number of points to load is more than the srs order".to_string()
            ))
        );
    }

    #[test]
    fn test_g2_power_of_2_readin() {
        use ark_bn254::{Fq, Fq2, G2Projective};
        use rust_kzg_bn254::helpers::is_on_curve_g2;
        use std::io::BufRead;

        let kzg = KZG::setup(
            "tests/test-files/g1.point",
            "",
            "tests/test-files/g2.point.powerOf2",
            3000,
            3000,
        )
        .unwrap();

        assert_eq!(kzg.get_g2_points().len(), 28);

        let file = File::open("tests/test-files/g2.powerOf2.string.txt").unwrap();
        let reader = BufReader::new(file);
        let kzg_g2_points = kzg.get_g2_points();

        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
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
    fn test_roots_of_unity_setup() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut kzg_clone1: KZG = KZG_3000.clone();
        let mut kzg_clone2: KZG = KZG_3000.clone();

        (0..10000).for_each(|_| {
            let blob_length: u64 = rand::thread_rng().gen_range(35..40000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();

            let input = Blob::from_raw_data(&random_blob);
            kzg_clone1
                .data_setup_custom(1, input.len().try_into().unwrap())
                .unwrap();
            kzg_clone2
                .calculate_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();

            let polynomial_input = input.to_polynomial_coeff_form();
            let expanded_roots_of_unity_vec_1: Vec<&Fr> = (0..polynomial_input.len())
                .map(|i| kzg_clone1.get_nth_root_of_unity(i).unwrap())
                .collect();
            let expanded_roots_of_unity_vec_2: Vec<&Fr> = (0..polynomial_input.len())
                .map(|i| kzg_clone2.get_nth_root_of_unity(i).unwrap())
                .collect();

            assert_eq!(expanded_roots_of_unity_vec_1, expanded_roots_of_unity_vec_2);
        });
    }

    #[test]
    fn test_blob_to_kzg_commitment() {
        use ark_bn254::Fq;

        let blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let fn_output = KZG_3000.commit_blob(&blob).unwrap();
        let commitment_from_da = G1Affine::new_unchecked(
            Fq::from_str(
                "2961155957874067312593973807786254905069537311739090798303675273531563528369",
            )
            .unwrap(),
            Fq::from_str(
                "159565752702690920280451512738307422982252330088949702406468210607852362941",
            )
            .unwrap(),
        );
        assert_eq!(commitment_from_da, fn_output);
    }

    #[test]
    fn test_compute_kzg_proof_random_100_blobs() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();

        (0..100).for_each(|_| {
            let blob_length = rand::thread_rng().gen_range(35..50000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();
            println!("generating blob of length is {}", blob_length);

            let input = Blob::from_raw_data(&random_blob);
            let input_poly = input.to_polynomial_eval_form();
            kzg.data_setup_custom(1, input.len().try_into().unwrap())
                .unwrap();

            let index =
                rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
            let commitment = kzg.commit_eval_form(&input_poly.clone()).unwrap();
            let proof = kzg
                .compute_kzg_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
                .unwrap();
            let value_fr = input_poly.get_at_index(index).unwrap();
            let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
            let pairing_result =
                kzg.verify_proof(commitment, proof, value_fr.clone(), z_fr.clone()).unwrap();
            assert_eq!(pairing_result, true);

            // take random index, not the same index and check
            assert_eq!(
                kzg.verify_proof(
                    commitment,
                    proof,
                    value_fr.clone(),
                    kzg.get_nth_root_of_unity(
                        (index + 1) % input_poly.len_underlying_blob_field_elements()
                    )
                    .unwrap()
                    .clone()
                ).unwrap(),
                false
            )
        })
    }

    #[test]
    fn test_compute_kzg_proof() {
        use rand::Rng;

        let mut kzg = KZG_INSTANCE.clone();

        let input = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly = input.to_polynomial_eval_form();

        for index in 0..input_poly.len() - 1 {
            kzg.data_setup_custom(4, input.len().try_into().unwrap())
                .unwrap();
            let mut rand_index =
                rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
            loop {
                if index == rand_index {
                    rand_index = rand::thread_rng()
                        .gen_range(0..input_poly.len_underlying_blob_field_elements());
                } else {
                    break;
                }
            }
            let commitment = kzg.commit_eval_form(&input_poly).unwrap();
            let proof = kzg
                .compute_kzg_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
                .unwrap();

            let value_fr = input_poly.get_at_index(index).unwrap();
            let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
            let pairing_result =
                kzg.verify_proof(commitment, proof, value_fr.clone(), z_fr.clone()).unwrap();
                
            assert_eq!(pairing_result, true);

            assert_eq!(
                kzg.verify_proof(
                    commitment,
                    proof,
                    value_fr.clone(),
                    kzg.get_nth_root_of_unity(rand_index).unwrap().clone()
                ).unwrap(),
                false
            )
        }
    }

    #[test]
    fn test_g1_ifft() {
        use ark_bn254::Fq;
        use std::io::BufRead;

        let file = File::open("tests/test-files/lagrangeG1SRS.txt").unwrap();
        let reader = BufReader::new(file);

        let kzg_g1_points = KZG_3000.g1_ifft(64).unwrap();

        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
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
    fn test_read_g1_point_from_bytes_be() {
        use ark_bn254::Fq;
        use ark_std::str::FromStr;
        use std::io::BufRead;

        let file = File::open("tests/test-files/srs.g1.points.string").unwrap();
        let reader = BufReader::new(file);
        let kzg_g1_points = KZG_3000.get_g1_points();

        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
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
    fn test_read_g2_point_from_bytes_be() {
        use ark_bn254::{Fq, Fq2};
        use ark_std::str::FromStr;
        use std::io::BufRead;

        let file = File::open("tests/test-files/srs.g2.points.string").unwrap();
        let reader = BufReader::new(file);
        let kzg_g2_points = KZG_3000.get_g2_points();

        let mut custom_points_list: usize = 0;
        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
            line = line.trim_end().to_string();

            let parts: Vec<&str> = line.split(',').collect();

            let x_c0 = Fq::from_str(parts[0]).expect("should be fine");
            let x_c1 = Fq::from_str(parts[1]).expect("should be fine");

            let y_c0 = Fq::from_str(parts[2]).expect("should be fine");
            let y_c1 = Fq::from_str(parts[3]).expect("should be fine");

            let x = Fq2::new(x_c0, x_c1);
            let y = Fq2::new(y_c0, y_c1);
            let point = G2Affine::new_unchecked(x, y);
            custom_points_list += 1;
            assert_eq!(point, kzg_g2_points[i]);
        }
        assert_eq!(custom_points_list, kzg_g2_points.len());
    }

    #[test]
    fn test_compute_quotient_eval_on_domain() {
        let z_fr = Fr::from_str(
            "18272962628503604941710624384101461447671738503426463821117705461905178580283",
        )
        .expect("yes");
        let value_fr = Fr::from_str(
            "179199642789798378766954615916637942576983085081216829572950655633119846502",
        )
        .expect("yes");
        let eval_raw: Vec<&str> = vec![
            "124448554745810004944228143885327110275920855486363883336842102793103679599",
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
            "0",
        ];

        let roots_of_unities_raw: Vec<&str> = vec![
            "1",
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
            "17229388088320038940941618493830445303168092387362094847263546333820121606543",
        ];

        let mut eval_fr: Vec<Fr> = vec![];
        let roots_of_unities: Vec<Fr> = helpers::str_vec_to_fr_vec(roots_of_unities_raw).unwrap();
        for i in 0..eval_raw.len() {
            eval_fr.push(Fr::from_str(eval_raw[i]).expect("yes"));
        }

        let result =
            KZG_3000.compute_quotient_eval_on_domain(&z_fr, &eval_fr, &value_fr, &roots_of_unities);
        let confirmed_result = Fr::from_str(
            "20008798420615294489302706738008175134837093401197634135729610787152508035605",
        )
        .expect("yes");

        assert_eq!(confirmed_result, result);
    }

    #[test]
    fn test_verify_blob_kzg_proof_batch_errors() {
        let mut kzg = KZG_INSTANCE.clone();

        let input = Blob::from_raw_data(b"randomafweggrrnwgiowrgub2grb4ht824t7935gtu");
        let input_poly = input
            .to_polynomial_eval_form();
        kzg.data_setup_custom(1, input.len().try_into().unwrap())
            .unwrap();

        let commitment = kzg.commit_eval_form(&input_poly).unwrap();
        let proof = kzg.compute_blob_kzg_proof(&input, &commitment).unwrap();

        let bad_commitment = G1Affine::new_unchecked(
            Fq::from_str(
                "2961155957874067312593973807786254905069537311739090798303675273531563528369",
            )
            .unwrap(),
            Fq::from_str(
                "2961155957874067312593973807786254905069537311739090798303675273531563528369",
            )
            .unwrap(),
        );

        let bad_proof = G1Affine::new_unchecked(
            Fq::from_str(
                "2961155957874067312593973807786254905069537311739090798303675273531563528369",
            )
            .unwrap(),
            Fq::from_str(
                "2961155957874067312593973807786254905069537311739090798303675273531563528369",
            )
            .unwrap(),
        );

        let pairing_result_bad_commitment = kzg.verify_blob_kzg_proof_batch(
            &vec![input.clone()],
            &vec![bad_commitment],
            &vec![proof],
        );
        assert_eq!(
            pairing_result_bad_commitment,
            Err(KzgError::CommitmentError(
                "commitment not on curve".to_string()
            ))
        );

        let pairing_result_bad_proof =
            kzg.verify_blob_kzg_proof_batch(&vec![input], &vec![commitment], &vec![bad_proof]);
        assert_eq!(
            pairing_result_bad_proof,
            Err(KzgError::CommitmentError("proof not on curve".to_string()))
        );
    }

    #[test]
    fn test_multiple_proof_random_100_blobs() {
        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();

        let mut blobs: Vec<Blob> = Vec::new();
        let mut commitments: Vec<G1Affine> = Vec::new();
        let mut proofs: Vec<G1Affine> = Vec::new();

        (0..100).for_each(|_| {
            let blob_length = rand::thread_rng().gen_range(35..50000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();
            println!("generating blob of length is {}", blob_length);

            let input = Blob::from_raw_data(&random_blob);
            let input_poly = input
                .to_polynomial_eval_form();
            kzg.data_setup_custom(1, input.len().try_into().unwrap())
                .unwrap();

            let commitment = kzg.commit_eval_form(&input_poly).unwrap();
            let proof = kzg.compute_blob_kzg_proof(&input, &commitment).unwrap();

            blobs.push(input);
            commitments.push(commitment);
            proofs.push(proof);
        });

        let mut bad_blobs = blobs.clone();
        let mut bad_commitments = commitments.clone();
        let mut bad_proofs = proofs.clone();

        let pairing_result = kzg
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
            .unwrap();
        assert_eq!(pairing_result, true);

        bad_blobs.pop();
        bad_blobs.push(Blob::from_raw_data(b"random"));
        let pairing_result_bad_blobs = kzg
            .verify_blob_kzg_proof_batch(&bad_blobs, &commitments, &proofs)
            .unwrap();
        assert_eq!(pairing_result_bad_blobs, false);

        bad_commitments.pop();
        bad_commitments.push(G1Affine::rand(&mut rng));
        let pairing_result_bad_commitments = kzg
            .verify_blob_kzg_proof_batch(&blobs, &bad_commitments, &proofs)
            .unwrap();
        assert_eq!(pairing_result_bad_commitments, false);

        bad_proofs.pop();
        bad_proofs.push(G1Affine::rand(&mut rng));
        let pairing_result_bad_proofs = kzg
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &bad_proofs)
            .unwrap();
        assert_eq!(pairing_result_bad_proofs, false);

        let pairing_result_everything_bad = kzg
            .verify_blob_kzg_proof_batch(&bad_blobs, &bad_commitments, &bad_proofs)
            .unwrap();
        assert_eq!(pairing_result_everything_bad, false);
    }

    #[test]
    fn test_compute_multiple_kzg_proof() {
        let mut kzg = KZG_INSTANCE.clone();
        let mut kzg2 = KZG_INSTANCE.clone();

        let input1 = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        kzg.data_setup_custom(4, input1.len().try_into().unwrap())
            .unwrap();

        let input_poly1 = input1.to_polynomial_eval_form();

        let commitment1 = kzg.commit_eval_form(&input_poly1.clone()).unwrap();
        let proof_1 = kzg.compute_blob_kzg_proof(&input1, &commitment1).unwrap();

        let mut reversed_input: Vec<u8> = vec![0; GETTYSBURG_ADDRESS_BYTES.len()];
        reversed_input.clone_from_slice(GETTYSBURG_ADDRESS_BYTES);
        reversed_input.reverse();

        let input2 = Blob::from_raw_data(
            b"17704588942648532530972307366230787358793284390049200127770755029903181125533",
        );
        kzg2.calculate_roots_of_unity(input2.len().try_into().unwrap())
            .unwrap();
        let input_poly2 = input2
            .to_polynomial_eval_form();

        let commitment2 = kzg2.commit_eval_form(&input_poly2).unwrap();

        let proof_2 = kzg2.compute_blob_kzg_proof(&input2, &commitment2).unwrap();

        let blobs = vec![input1, input2];
        let commitments = vec![commitment1, commitment2];
        let proofs = vec![proof_1, proof_2];
        // let res = kzg.verify_blob_kzg_proof(&input1, &commitment1, &auto_proof).unwrap();

        let pairing_result = kzg
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
            .unwrap();

        assert_eq!(pairing_result, true);
    }
}
