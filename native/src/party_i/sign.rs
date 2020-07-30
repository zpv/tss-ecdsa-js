use neon::prelude::*;
use std::time;

use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::*;
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
use neon_serde::export;
use paillier::*;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zk_paillier::zkproofs::DLogStatement;

use crate::party_i::{
  broadcast, hd_keys, poll_for_broadcasts, poll_for_p2p, sendp2p, Params, PartySignup,
};

pub fn sign_message(mut cx: FunctionContext) -> JsResult<JsString> {
  let js_arr_handle = cx.argument::<JsValue>(0)?;

  println!("hello!1");

  let addr = cx.argument::<JsString>(1)?.value() as String;
  println!("hello!2");

  println!("{:?}", cx.argument::<JsString>(2)?.value());

  let path = cx.argument::<JsString>(2)?.value() as String;
  println!("hello!3");

  let threshold = cx.argument::<JsNumber>(3)?.value() as u16;
  println!("hello!4");

  let parties = cx.argument::<JsNumber>(4)?.value() as u16;
  println!("hello!5");

  let message = cx.argument::<JsString>(5)?.value() as String;
  println!("hello!6");

  let sign_at_path = !path.is_empty();

  println!("hello!");

  let (
    party_keys,
    shared_keys,
    party_id,
    pk_vec,
    mut vss_scheme_vec,
    y_sum,
    ek_vec,
    dlog_statement_vec,
  ): (
    Keys,
    SharedKeys,
    u16,
    Vec<GE>,
    Vec<VerifiableSS>,
    GE,
    Vec<EncryptionKey>,
    Vec<DLogStatement>,
  ) = neon_serde::from_value(&mut cx, js_arr_handle)?;
  println!(":68");

  let (f_l_new, y_sum) = match path.is_empty() {
    true => (ECScalar::zero(), y_sum),
    false => {
      let path_vector: Vec<BigInt> = path
        .split('/')
        .map(|s| s.trim().parse::<BigInt>().unwrap())
        .collect();
      let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&y_sum, path_vector.clone());
      (f_l_new, y_sum_child.clone())
    }
  };
  println!(":81");

  let client = Client::new();
  let delay = time::Duration::from_millis(25);

  let params = Params {
    threshold: threshold.to_string(),
    parties: parties.to_string(),
  };

  // Signup
  let (party_num_int, uuid) = match signup(&addr, &client, &params).unwrap() {
    PartySignup { number, uuid } => (number, uuid),
  };
  println!("number: {:?}, uuid: {:?}", party_num_int, uuid);
  println!(":96");

  // round 0: collect signers IDs
  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round0",
    serde_json::to_string(&party_id).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  let round0_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round0",
    uuid.clone(),
  );

  println!(":119");

  let mut j = 0;
  let mut signers_vec: Vec<usize> = Vec::new();
  for i in 1..=threshold + 1 {
    if i == party_num_int {
      signers_vec.push((party_id - 1) as usize);
    } else {
      let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
      signers_vec.push((signer_j - 1) as usize);
      j = j + 1;
    }
  }

  if sign_at_path == true {
    // optimize!
    let g: GE = ECPoint::generator();
    // apply on first commitment for leader (leader is party with num=1)
    let com_zero_new = vss_scheme_vec[0].commitments[0] + g * f_l_new;
    // println!("old zero: {:?}, new zero: {:?}", vss_scheme_vec[0].commitments[0], com_zero_new);
    // get iterator of all commitments and skip first zero commitment
    let mut com_iter_unchanged = vss_scheme_vec[0].commitments.iter();
    com_iter_unchanged.next().unwrap();
    // iterate commitments and inject changed commitments in the beginning then aggregate into vector
    let com_vec_new = (0..vss_scheme_vec[1].commitments.len())
      .map(|i| {
        if i == 0 {
          com_zero_new
        } else {
          com_iter_unchanged.next().unwrap().clone()
        }
      })
      .collect::<Vec<GE>>();
    let new_vss = VerifiableSS {
      parameters: vss_scheme_vec[0].parameters.clone(),
      commitments: com_vec_new,
    };
    // replace old vss_scheme for leader with new one at position 0
    //    println!("comparing vectors: \n{:?} \nand \n{:?}", vss_scheme_vec[0], new_vss);

    vss_scheme_vec.remove(0);
    vss_scheme_vec.insert(0, new_vss);
    //    println!("NEW VSS VECTOR: {:?}", vss_scheme_vec);
  }

  let mut private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

  if sign_at_path == true {
    if party_num_int == 1 {
      // update u_i and x_i for leader
      private = private.update_private_key(&f_l_new, &f_l_new);
    } else {
      // only update x_i for non-leaders
      private = private.update_private_key(&FE::zero(), &f_l_new);
    }
  }

  let sign_keys = SignKeys::create(
    &private,
    &vss_scheme_vec[signers_vec[(party_num_int - 1) as usize]],
    signers_vec[(party_num_int - 1) as usize],
    &signers_vec,
  );

  // SIGN PHASES BEGIN

  let (com, decommit) = sign_keys.phase1_broadcast();
  let m_a_k = MessageA::a(&sign_keys.k_i, &party_keys.ek);

  println!(":187");

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round1",
    serde_json::to_string(&(com.clone(), m_a_k.0.clone())).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  let round1_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round1",
    uuid.clone(),
  );

  let mut j = 0;
  let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
  let mut m_a_vec: Vec<MessageA> = Vec::new();

  println!(":212");

  for i in 1..threshold + 2 {
    if i == party_num_int {
      bc1_vec.push(com.clone());
    //   m_a_vec.push(m_a_k.clone());
    } else {
      //     if signers_vec.contains(&(i as usize)) {
      println!("Unpacking {:?}", i);
      println!("Unpacking {:?}", &round1_ans_vec[j]);

      println!(
        "{:?}",
        serde_json::from_str::<(SignBroadcastPhase1, MessageA)>(&round1_ans_vec[j])
      );

      let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
        serde_json::from_str(&round1_ans_vec[j]).unwrap();
      bc1_vec.push(bc1_j);
      m_a_vec.push(m_a_party_j);

      j = j + 1;
      //       }
    }
  }
  assert_eq!(signers_vec.len(), bc1_vec.len());

  // Phase 2: Perform MtA share conversion subprotocol

  let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
  let mut beta_vec: Vec<FE> = Vec::new();
  let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
  let mut ni_vec: Vec<FE> = Vec::new();
  let mut j = 0;

  for i in 1..threshold + 2 {
    if i != party_num_int {
      let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
        &sign_keys.gamma_i,
        &ek_vec[signers_vec[(i - 1) as usize]],
        m_a_vec[j].clone(),
      );
      let (m_b_w, beta_wi, _, _) = MessageB::b(
        &sign_keys.w_i,
        &ek_vec[signers_vec[(i - 1) as usize]],
        m_a_vec[j].clone(),
      );
      m_b_gamma_send_vec.push(m_b_gamma);
      m_b_w_send_vec.push(m_b_w);
      beta_vec.push(beta_gamma);
      ni_vec.push(beta_wi);
      j = j + 1;
    }
  }

  let mut j = 0;
  for i in 1..threshold + 2 {
    if i != party_num_int {
      assert!(sendp2p(
        &addr,
        &client,
        party_num_int.clone(),
        i.clone(),
        "round2",
        serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone())).unwrap(),
        uuid.clone(),
      )
      .is_ok());
      j = j + 1;
    }
  }

  let round2_ans_vec = poll_for_p2p(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round2",
    uuid.clone(),
  );

  let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
  let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

  for i in 0..threshold {
    let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
      serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
    m_b_gamma_rec_vec.push(m_b_gamma_i);
    m_b_w_rec_vec.push(m_b_w_i);
  }

  let mut alpha_vec: Vec<FE> = Vec::new();
  let mut miu_vec: Vec<FE> = Vec::new();
  let mut miu_bigint_vec = Vec::new(); //required for the phase6 IA sub protocol

  let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
  let mut j = 0;
  for i in 1..threshold + 2 {
    //        println!("mbproof p={}, i={}, j={}", party_num_int, i, j);
    if i != party_num_int {
      //            println!("verifying: p={}, i={}, j={}", party_num_int, i, j);
      let m_b = m_b_gamma_rec_vec[j].clone();

      let alpha_ij_gamma = m_b
        .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
        .expect("wrong dlog or m_b");
      let m_b = m_b_w_rec_vec[j].clone();
      let alpha_ij_wi = m_b
        .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
        .expect("wrong dlog or m_b");
      alpha_vec.push(alpha_ij_gamma.0);
      miu_vec.push(alpha_ij_wi.0);
      miu_bigint_vec.push(alpha_ij_wi.1);

      let g_w_i = Keys::update_commitments_to_xi(
        &xi_com_vec[signers_vec[(i - 1) as usize]],
        &vss_scheme_vec[signers_vec[(i - 1) as usize]],
        signers_vec[(i - 1) as usize],
        &signers_vec,
      );
      //println!("Verifying client {}", party_num_int);
      assert_eq!(m_b.b_proof.pk.clone(), g_w_i);
      //println!("Verified client {}", party_num_int);
      j = j + 1;
    }
  }

  // Phase 3: Build delta
  let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
  let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round3",
    serde_json::to_string(&delta_i).unwrap(),
    uuid.clone(),
  )
  .is_ok());
  let round3_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round3",
    uuid.clone(),
  );
  let mut delta_vec: Vec<FE> = Vec::new();
  format_vec_from_reads(
    &round3_ans_vec,
    party_num_int as usize,
    delta_i,
    &mut delta_vec,
  );
  let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

  let (T_i, l_i) = SignKeys::phase3_compute_t_i(&sigma);

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round3_b",
    serde_json::to_string(&T_i).unwrap(),
    uuid.clone(),
  )
  .is_ok());
  let round3b_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round3_b",
    uuid.clone(),
  );

  println!(":397");

  let mut T_vec: Vec<GE> = Vec::new();
  format_vec_from_reads(&round3b_ans_vec, party_num_int as usize, T_i, &mut T_vec);

  // Phase 4: Decommit to gamma_i

  println!(":377");

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round4",
    serde_json::to_string(&decommit).unwrap(),
    uuid.clone(),
  )
  .is_ok());
  let round4_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round4",
    uuid.clone(),
  );

  println!(":397");

  let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
  format_vec_from_reads(
    &round4_ans_vec,
    party_num_int as usize,
    decommit,
    &mut decommit_vec,
  );

  println!(":407");

  // let decomm_i = decommit_vec.remove((party_num_int - 1) as usize);
  // bc1_vec.remove((party_num_int - 1) as usize);
  println!(":412");
  println!(":LEN! {:?}", m_b_gamma_rec_vec.len());
  let b_proof_vec = (0..m_b_gamma_rec_vec.len())
    .map(|i| &m_b_gamma_rec_vec[i].b_proof)
    .collect::<Vec<&DLogProof>>();
  println!(":416");
  println!("len {:?}", b_proof_vec.len());

  let R = SignKeys::phase4(
    &delta_inv,
    &b_proof_vec,
    decommit_vec,
    &bc1_vec,
    (party_num_int - 1) as usize,
  )
  .expect("bad gamma_i decommit");
  println!(":426");

  let R_dash = R * sign_keys.k_i;

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round5_a",
    serde_json::to_string(&(R.clone(), R_dash.clone())).unwrap(),
    uuid.clone(),
  )
  .is_ok());
  let round5a_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round5_a",
    uuid.clone(),
  );

  let mut R_and_R_dash_vec: Vec<(GE, GE)> = Vec::new();
  format_vec_from_reads(
    &round5a_ans_vec,
    party_num_int as usize,
    (R, R_dash),
    &mut R_and_R_dash_vec,
  );

  let (R_vec, R_dash_vec): (Vec<_>, Vec<_>) = R_and_R_dash_vec.iter().cloned().unzip();

  let mut phase5_proofs: Vec<PDLwSlackProof> = Vec::new();

  for i in 1..threshold + 2 {
    if i != party_num_int {
      let proof = LocalSignature::phase5_proof_pdl(
        &R_dash,
        &R,
        &m_a_k.0.c,
        &ek_vec[signers_vec[(party_num_int - 1) as usize]],
        &sign_keys.k_i,
        &m_a_k.1,
        &party_keys,
        &dlog_statement_vec[signers_vec[(i - 1) as usize]],
      );

      phase5_proofs.push(proof);
    }
  }

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round5_b",
    serde_json::to_string(&phase5_proofs).unwrap(),
    uuid.clone(),
  )
  .is_ok());
  let round5b_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round5_b",
    uuid.clone(),
  );

  let mut phase5_proofs_vec: Vec<Vec<PDLwSlackProof>> = Vec::new();
  format_vec_from_reads(
    &round5b_ans_vec,
    party_num_int as usize,
    phase5_proofs,
    &mut phase5_proofs_vec,
  );
  LocalSignature::phase5_check_R_dash_sum(&R_dash_vec).expect("check failed");
  // adding local g_gamma_i
  // let R = R + decomm_i.g_gamma_i * &delta_inv;

  let S_i_and_proof =
    LocalSignature::phase6_compute_S_i_and_proof_of_consistency(&R, &T_i, &sigma, &l_i);

  println!(":511");

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round6",
    serde_json::to_string(&S_i_and_proof).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  println!(":523");

  let round6_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round6",
    uuid.clone(),
  );

  println!(":536");

  let mut phase6_tuple_vec: Vec<(GE, HomoELGamalProof)> = Vec::new();
  format_vec_from_reads(
    &round6_ans_vec,
    party_num_int as usize,
    S_i_and_proof,
    &mut phase6_tuple_vec,
  );

  let (S_vec, homo_elgamal_proof_vec): (Vec<_>, Vec<_>) = phase6_tuple_vec.iter().cloned().unzip();
  LocalSignature::phase6_verify_proof(&S_vec, &homo_elgamal_proof_vec, &R_vec, &T_vec)
    .expect("Proof verification failed");

  LocalSignature::phase6_check_S_i_sum(&y_sum, &S_vec).expect("S_i checksum failed");

  println!(":545");

  let message = match hex::decode(message.clone()) {
    Ok(x) => x,
    Err(_e) => message.as_bytes().to_vec(),
  };
  let message = &message[..];

  let message_bn = BigInt::from(message);
  //    println!("message_bn INT: {}", message_bn);
  let message_int = BigInt::from(message);
  let two = BigInt::from(2);
  let message_bn = message_bn.modulus(&two.pow(256));

  let local_sig = LocalSignature::phase7_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

  assert!(broadcast(
    &addr,
    &client,
    party_num_int,
    "round7",
    serde_json::to_string(&local_sig).unwrap(),
    uuid.clone(),
  )
  .is_ok());

  let round7_ans_vec = poll_for_broadcasts(
    &addr,
    &client,
    party_num_int,
    threshold + 1,
    delay,
    "round7",
    uuid.clone(),
  );

  println!(":536");

  let mut local_sig_vec: Vec<LocalSignature> = Vec::new();
  format_vec_from_reads(
    &round7_ans_vec,
    party_num_int as usize,
    local_sig,
    &mut local_sig_vec,
  );

  let s_vec = local_sig_vec
    .iter()
    .map(|sig| sig.s_i.clone())
    .collect::<Vec<_>>();

  let sig = local_sig_vec[0].output_signature(&s_vec[1..]);
  assert_eq!(local_sig_vec[0].y, y_sum);

  let sig = sig.unwrap();

  verify(&sig, &y_sum, &message_bn).expect("signature verification failed");

  let ret_dict = json!({
      "r": (BigInt::from(&(sig.r.get_element())[..])).to_str_radix(16),
      "s": (BigInt::from(&(sig.s.get_element())[..])).to_str_radix(16),
      "status": "signature_ready",
      "recid": sig.recid.clone(),
      "x": &y_sum.x_coor(),
      "y": &y_sum.y_coor(),
      "msg_int": message_int,
  });

  println!("{}", ret_dict.to_string());
  Ok(cx.string(ret_dict.to_string()))
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
  ans_vec: &'a Vec<String>,
  party_num: usize,
  value_i: T,
  new_vec: &'a mut Vec<T>,
) {
  let mut j = 0;
  for i in 1..ans_vec.len() + 2 {
    if i == party_num {
      new_vec.push(value_i.clone());
    } else {
      let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
      new_vec.push(value_j);
      j = j + 1;
    }
  }
}

pub fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> Option<String>
where
  T: serde::ser::Serialize,
{
  let res = client
    .post(&format!("{}/{}", addr, path))
    .json(&body)
    .send();
  Some(res.unwrap().text().unwrap())
}

pub fn signup(addr: &String, client: &Client, params: &Params) -> Result<PartySignup, ()> {
  let res_body = postb(&addr, &client, "signupsign", params).unwrap();
  let answer: Result<PartySignup, ()> = serde_json::from_str(&res_body).unwrap();
  return answer;
}
