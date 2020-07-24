use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::{iter::repeat, thread, time, time::Duration};

use crypto::{
  aead::{AeadDecryptor, AeadEncryptor},
  aes::KeySize::KeySize256,
  aes_gcm::AesGcm,
};

pub mod keygen;

pub type Key = String;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
  pub ciphertext: Vec<u8>,
  pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
  pub number: u16,
  pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
  pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
  pub key: Key,
  pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Params {
  pub parties: String,
  pub threshold: String,
}

// nonce reuse!
// fine in this case since one-time message in keygen
#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> AEAD {
  let nonce: Vec<u8> = repeat(3).take(12).collect();
  let aad: [u8; 0] = [];
  let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
  let mut out: Vec<u8> = repeat(0).take(plaintext.len()).collect();
  let mut out_tag: Vec<u8> = repeat(0).take(16).collect();
  gcm.encrypt(&plaintext[..], &mut out[..], &mut out_tag[..]);
  AEAD {
    ciphertext: out.to_vec(),
    tag: out_tag.to_vec(),
  }
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Vec<u8> {
  let mut out: Vec<u8> = repeat(0).take(aead_pack.ciphertext.len()).collect();
  let nonce: Vec<u8> = repeat(3).take(12).collect();
  let aad: [u8; 0] = [];
  let mut gcm = AesGcm::new(KeySize256, key, &nonce[..], &aad);
  gcm.decrypt(&aead_pack.ciphertext[..], &mut out, &aead_pack.tag[..]);
  out
}

pub fn postb<T>(addr: &String, client: &Client, path: &str, body: T) -> Option<String>
where
  T: serde::ser::Serialize,
{
  //    let mut addr = env::args()
  //        .nth(4)
  //        .unwrap_or_else(|| "http://127.0.0.1:8001".to_string());
  //    for argument in env::args() {
  //        if argument.contains("://") {
  //            let addr_parts: Vec<&str> = argument.split("http:").collect();
  //            addr = format!("http:{}", addr_parts[1]);
  //        }
  //    }
  let retries = 3;
  let retry_delay = time::Duration::from_millis(250);
  for _i in 1..retries {
    let addr = format!("{}/{}", addr, path);
    let res = client.post(&addr).json(&body).send();

    if let Ok(res) = res {
      return Some(res.text().unwrap());
    }
    thread::sleep(retry_delay);
  }
  None
}

pub fn sendp2p(
  addr: &String,
  client: &Client,
  party_from: u16,
  party_to: u16,
  round: &str,
  data: String,
  sender_uuid: String,
) -> Result<(), ()> {
  let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

  let entry = Entry {
    key: key.clone(),
    value: data,
  };

  let res_body = postb(&addr, &client, "set", entry).unwrap();
  serde_json::from_str(&res_body).unwrap()
}

pub fn broadcast(
  addr: &String,
  client: &Client,
  party_num: u16,
  round: &str,
  data: String,
  sender_uuid: String,
) -> Result<(), ()> {
  let key = format!("{}-{}-{}", party_num, round, sender_uuid);
  let entry = Entry {
    key: key.clone(),
    value: data,
  };

  let res_body = postb(&addr, &client, "set", entry).unwrap();
  serde_json::from_str(&res_body).unwrap()
}

pub fn poll_for_broadcasts(
  addr: &String,
  client: &Client,
  party_num: u16,
  n: u16,
  delay: Duration,
  round: &str,
  sender_uuid: String,
) -> Vec<String> {
  let mut ans_vec = Vec::new();
  for i in 1..=n {
    if i != party_num {
      let key = format!("{}-{}-{}", i, round, sender_uuid);
      let index = Index { key };
      loop {
        // add delay to allow the server to process request:
        thread::sleep(delay);
        let res_body = postb(&addr, &client, "get", index.clone()).unwrap();
        let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
        if let Ok(answer) = answer {
          ans_vec.push(answer.value);
          println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
          break;
        }
      }
    }
  }
  ans_vec
}

pub fn poll_for_p2p(
  addr: &String,
  client: &Client,
  party_num: u16,
  n: u16,
  delay: Duration,
  round: &str,
  sender_uuid: String,
) -> Vec<String> {
  let mut ans_vec = Vec::new();
  for i in 1..=n {
    if i != party_num {
      let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
      let index = Index { key };
      loop {
        // add delay to allow the server to process request:
        thread::sleep(delay);
        let res_body = postb(&addr, &client, "get", index.clone()).unwrap();
        let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
        if let Ok(answer) = answer {
          ans_vec.push(answer.value);
          println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
          break;
        }
      }
    }
  }
  ans_vec
}
