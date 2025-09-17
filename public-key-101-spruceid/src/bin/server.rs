#[macro_use] extern crate rocket;

use std::time::{Instant,
                Duration};

use base16::{decode as b16_decode,  
             encode_lower as b16_encode_lower};
use dashmap::DashMap;
use did_key::*;
use rocket::{Request,
             State};
use rocket::http::Status;
use rocket::request::{FromRequest,
                      Outcome};
use textnonce::TextNonce;
use urlencoding::{decode as urldecode,
                  encode as urlencode};

type DidKeyURI = String;

struct DidKeySigned;

#[derive(Debug)]
enum DidKeySignatureError {
    Missing,
    Invalid,
}

#[derive(Clone)]
struct NonceTime {
    nonce: String,
    time: Instant
}

struct NonceCache {
    cache: DashMap<DidKeyURI, NonceTime>
}

#[get("/")]
fn index() -> &'static str {
    return "PK 101 demo!\n/present-did-key/<did_key_uri>\n/validate-nonce/<did_key_uri>/<nonce>";
}

/// Client side API for requesting a nonce.  
///
/// It (upon presentation of a public did key uri that successfully resolves)
/// generates a new nonce and stores it in the nonce cache for later verification
#[get("/present-did-key/<did_key_uri>")]
fn present_key(did_key_uri: &str, nonce_cache: &State<NonceCache>) -> String {
    let key_uri = urldecode(did_key_uri).expect("did_key_uri should urldecode successfully");
    // validate did_key uri by resolving it
    let _key = resolve(key_uri.as_ref()).expect("did:key should resolve correctly");
    // generate and store nonce for that key
    let nonce = TextNonce::new().into_string();
    let encoded_nonce = urlencode(&nonce).into_owned();
    let nonce_time = NonceTime{nonce: encoded_nonce,
                               time: Instant::now()};

    nonce_cache.cache.insert(key_uri.to_string(), nonce_time.clone());

    // respond with that nonce
    nonce_time.nonce
}

/// This is a testing stub, probably to be removed in a production app but I don't know how to do
/// that right now but its purpose is to 
/// 1. generate a new did_key_uri
/// 2. generate a text nonce and store it in the nonce cache
/// 3. sign the /validate-nonce request and return that value so the user can use it in testing the
///    /validate-nonce path
#[get("/testing-request")]
fn testing_request(nonce_cache: &State<NonceCache>) -> String {
    let key = generate::<Ed25519KeyPair>(None);
    let did_key_uri = "did:key:".to_owned() + &key.fingerprint();
    let did_key_uri_encoded = urlencode(&did_key_uri).to_string();

    let nonce = TextNonce::new().into_string();
    let encoded_nonce = urlencode(&nonce).into_owned();
    let nonce_time = NonceTime{nonce: encoded_nonce.clone(), 
                               time: Instant::now()};

    nonce_cache.cache.insert(did_key_uri_encoded.clone(), nonce_time.clone());

    let signing_path = format!("/validate-nonce/{did_key_uri_encoded}/{encoded_nonce}");
    let sig = key.sign(signing_path.as_bytes());
    let sig_encoded = b16_encode_lower(&sig);

    let header = format!("did-key-signature: {sig_encoded}");
    let curl_command = format!("curl -H \"{header}\" http://localhost:8000/validate-nonce/{did_key_uri_encoded}/{encoded_nonce}");
    
    curl_command.to_string()
}

#[get("/validate-nonce/<did_key_uri>/<nonce_value>")]
fn validate_nonce(did_key_uri: &str, 
                  nonce_value: &str, 
                  nonce_cache: &State<NonceCache>,
                  _did_key_signed: DidKeySigned) -> String 
{
    // did_key signed request and (this comes from Req Guard)
    //   nonce in cache and 
    //   its timely and 
    //   it is equivalent to nonce value provided
    
    fn check_nonce(nonce_time: NonceTime, nonce_value: &str) -> bool {
        nonce_time.nonce == nonce_value && 
            Instant::now() < nonce_time.time + Duration::new(60*5, 0)
    }

    match nonce_cache.cache.get(did_key_uri) {
        None => String::from("Invalid"),
        Some(nt) => if check_nonce(nt.clone(), nonce_value) { String::from("Valid") } 
                    else { String::from("Invalid") }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for DidKeySigned {
    type Error = DidKeySignatureError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        fn did_did_key_sign(path: &str, did_key_uri: &str, signature: &str) -> bool {
           let key_uri = urldecode(did_key_uri).expect("did_key_uri should urldecode successfully");
           let key = resolve(key_uri.as_ref()).expect("did:key should resolve correctly");
           let decoded_sig = b16_decode(signature).expect("Should decode from b16");
           let ver = key.verify(path.as_bytes(), &decoded_sig);
           matches!(ver, Ok(()))
        }

        let path = req.uri().path();

        if let Some(did_key_uri) = req.param(1) {
            match req.headers().get_one("did-key-signature") {
                None => {eprintln!("Missing"); Outcome::Error((Status::BadRequest, DidKeySignatureError::Missing))},
                Some(signature) if did_did_key_sign(&path.to_string(),
                                                    did_key_uri.expect("did key uri param should exist as first param"),
                                                    signature) => Outcome::Success(DidKeySigned),
                Some(_) => {eprintln!("Invalid Sig"); Outcome::Error((Status::BadRequest, DidKeySignatureError::Invalid))}
            }
        }
        else {
            eprintln!("Else");
            Outcome::Error((Status::BadRequest, DidKeySignatureError::Missing))
        }
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().
        manage(NonceCache{cache: DashMap::new()}).
        mount("/", routes![index, present_key, validate_nonce, testing_request])
}
