use base16::encode_lower as b16_encode_lower;
use did_key::*;
use reqwest::blocking::Client;
use urlencoding::encode as urlencode;

const HOST: &str = "http://localhost:8000";

fn main() -> () {
    let reqwest_client = Client::new();

    // did key generation
    let key = generate::<Ed25519KeyPair>(None);
    println!("Our key fingerprint: {}", key.fingerprint());

    let did_key_uri = "did:key:".to_owned() + &key.fingerprint();
    let encoded_did_key_uri = urlencode(&did_key_uri);
    let present_dk_path = format!("/present-did-key/{}", encoded_did_key_uri);
    let present_request_uri = format!("{}/{}", HOST, present_dk_path);

    let maybe_nonce = reqwest_client
        .get(present_request_uri)
        .send()
        .expect("There should be a nonce response")
        .text()
        .expect("There should be a nonce here");
    println!("{}", maybe_nonce);

    let encoded_nonce = urlencode(&maybe_nonce);
    let path_to_sign = format!("/validate-nonce/{}/{}", encoded_did_key_uri, encoded_nonce);

    let signature = key.sign(path_to_sign.as_bytes());
    let sig_encoded = b16_encode_lower(&signature);
    let header_k = "did-key-signature";

    let validate_req_uri = format!("{}{}", HOST, path_to_sign);

    let resp = reqwest_client
        .get(validate_req_uri)
        .header(header_k, sig_encoded)
        .send()
        .expect("We should get a response from the server")
        .text()
        .expect("We should get text respons");
    println!("{}", resp);
    std::process::exit(0);
}

//Scratchwork
//
//let did_doc_pub = key.get_did_document(CONFIG_JOSE_PUBLIC);
//let did_doc_pub_json = serde_json::to_string_pretty(&did_doc_pub).unwrap();

//fs::write("client_key_diddoc.pub", did_doc_pub_json)
//  .expect("Should be able to write client key");

//let did_doc_priv = key.get_did_document(CONFIG_JOSE_PRIVATE);
//let did_doc_priv_json = serde_json::to_string_pretty(&did_doc_priv).unwrap();

//fs::write("client_key_diddoc.priv", did_doc_priv_json)
//  .expect("Should be able to write client key");

// This automagically gets on the server from the generated key
//let client_didkey_uri =
//"did:key:z6MktXYuXzWsjSrWEJCDKKUtjnsze9bpxiQzFLonRQa4TrT1"

//let client_priv_key = fs::read("client_key_diddoc.priv").expect("Should be able to read this file");
//let did_key_str = str::from_utf8(&client_priv_key).expect("Should be able to decode from utf8");
//let did_key_jws = decode_jws(did_key_str);
//println!("{:?}", &did_key_jws);

//let client_provided_uri = "did:key:".to_owned() + &key.fingerprint();
//println!("{}", &client_provided_uri);

// Server provides nonce
//let nonce = textnonce::TextNonce::new();

// We respond with that signed nonce
//let sig = key.sign(nonce.clone().into_string().as_bytes());
//let msg = b"foo bar baz";
//let sig = key.sign(msg);
//let ver = key.verify(msg, &sig).expect("This should work");
//let ver = key.verify(nonce.into_string().as_bytes(), &sig);
//matches!(ver, ());
