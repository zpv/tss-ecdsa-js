extern crate curv;

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hmac_sha512;
use curv::cryptographic_primitives::hashing::traits::KeyedHash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::*;
use paillier::*;
use serde_json::json;
use zk_paillier::zkproofs::DLogStatement;

use neon::prelude::*;

pub fn get_hd_key(y_sum: &GE, path_vector: Vec<BigInt>) -> (GE, FE) {
  // generate a random but shared chain code, this will do
  let chain_code = GE::generator();
  //    println!("chain code {:?}", chain_code);
  // derive a new pubkey and LR sequence, y_sum becomes a new child pub key
  let (y_sum_child, f_l_new, _cc_new) = hd_key(
    path_vector,
    &y_sum,
    &chain_code.bytes_compressed_to_big_int(),
  );
  let y_sum = y_sum_child.clone();
  //    println!("New public key: {:?}", &y_sum);
  //    println!("Public key X: {:?}", &y_sum.x_coor());
  //    println!("Public key Y: {:?}", &y_sum.y_coor());
  (y_sum, f_l_new)
}

pub fn hd_key(
  mut location_in_hir: Vec<BigInt>,
  pubkey: &GE,
  chain_code_bi: &BigInt,
) -> (GE, FE, GE) {
  let mask = BigInt::from(2).pow(256) - BigInt::one();
  // let public_key = self.public.q.clone();

  // calc first element:
  let first = location_in_hir.remove(0);
  let pub_key_bi = pubkey.bytes_compressed_to_big_int();
  let f = hmac_sha512::HMacSha512::create_hmac(&chain_code_bi, &[&pub_key_bi, &first]);
  let f_l = &f >> 256;
  let f_r = &f & &mask;
  let f_l_fe: FE = ECScalar::from(&f_l);
  let f_r_fe: FE = ECScalar::from(&f_r);

  let bn_to_slice = BigInt::to_vec(chain_code_bi);
  let chain_code = GE::from_bytes(&bn_to_slice[1..33]).unwrap() * &f_r_fe;
  let g: GE = ECPoint::generator();
  let pub_key = *pubkey + g * &f_l_fe;

  let (public_key_new_child, f_l_new, cc_new) =
    location_in_hir
      .iter()
      .fold((pub_key, f_l_fe, chain_code), |acc, index| {
        let pub_key_bi = acc.0.bytes_compressed_to_big_int();
        let f = hmac_sha512::HMacSha512::create_hmac(
          &acc.2.bytes_compressed_to_big_int(),
          &[&pub_key_bi, index],
        );
        let f_l = &f >> 256;
        let f_r = &f & &mask;
        let f_l_fe: FE = ECScalar::from(&f_l);
        let f_r_fe: FE = ECScalar::from(&f_r);

        (acc.0 + g * &f_l_fe, f_l_fe + &acc.1, &acc.2 * &f_r_fe)
      });
  (public_key_new_child, f_l_new, cc_new)
}

pub fn get_pubkey(mut cx: FunctionContext) -> JsResult<JsString> {
  let js_arr_handle = cx.argument::<JsValue>(0)?;
  let path = cx.argument::<JsString>(1)?.value() as String;

  let (_, _, _, _, _, y_sum, _, _): (
    Keys,
    SharedKeys,
    u16,
    Vec<GE>,
    Vec<VerifiableSS>,
    GE,
    Vec<EncryptionKey>,
    Vec<DLogStatement>,
  ) = neon_serde::from_value(&mut cx, js_arr_handle)?;

  let (_, y_sum) = match path.is_empty() {
    true => (ECScalar::zero(), y_sum),
    false => {
      let path_vector: Vec<BigInt> = path
        .split('/')
        .map(|s| s.trim().parse::<BigInt>().unwrap())
        .collect();
      let (y_sum_child, f_l_new) = get_hd_key(&y_sum, path_vector.clone());
      (f_l_new, y_sum_child.clone())
    }
  };

  let ret_dict = json!({
      "x": &y_sum.x_coor(),
      "y": &y_sum.y_coor(),
      "path": path,
  });

  Ok(cx.string(ret_dict.to_string()))
}
