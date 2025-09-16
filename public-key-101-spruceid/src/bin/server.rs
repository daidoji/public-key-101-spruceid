#[macro_use] extern crate rocket;

use std::time::{Instant,
                Duration};

use dashmap::DashMap;
use did_key::*;
use rocket::{Request,
             State};
use rocket::http::Status;
use rocket::request::{FromRequest,
                      Outcome};
use textnonce::TextNonce;
use urlencoding::{decode,
                  encode};

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

#[get("/present-did-key/<did_key_uri>")]
fn present_key(did_key_uri: &str, nonce_cache: &State<NonceCache>) -> String {
    let key_uri = decode(did_key_uri).expect("did_key_uri should urldecode successfully");
    // validate did_key uri by resolving it
    let _key = resolve(key_uri.as_ref()).expect("did:key should resolve correctly");
    // generate and store nonce for that key
    let nonce = TextNonce::new().into_string();
    let encoded_nonce = encode(&nonce).into_owned();
    let nonce_time = NonceTime{nonce: encoded_nonce, time: Instant::now()};

    nonce_cache.cache.insert(key_uri.to_string(), nonce_time.clone());

    // respond with that nonce
    return nonce_time.nonce;
}

#[get("/sign-request/<did_key_uri>/<nonce_value>")]
fn sign_request(did_key_uri: &str, nonce_value: &str) -> String {
   let key_uri = decode(did_key_uri).expect("did_key_uri should urldecode successfully");
   let key = resolve(key_uri.as_ref()).expect("did:key should resolve correctly");
   let sig = key.sign(b"/validate-nonce/{did_key_uri}/{nonce_value}");
   String::from_utf8(sig).unwrap()
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
        fn did_did_key_sign(route: &str, did_key_uri: &str, signature: &str) -> bool {
           let key_uri = decode(did_key_uri).expect("did_key_uri should urldecode successfully");
           let key = resolve(key_uri.as_ref()).expect("did:key should resolve correctly");
           let ver = key.verify(route.as_bytes(), signature.as_bytes());
           matches!(ver, Ok(()))
        }

        if let Some(route) = req.route() && let Some(did_key_uri) = req.param(0) {
            match req.headers().get_one("did-key-signature") {
                None => {eprintln!("Missing"); Outcome::Error((Status::BadRequest, DidKeySignatureError::Missing))},
                Some(signature) if did_did_key_sign((route.name.clone()).expect("Route name should exist").as_ref(),
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
        mount("/", routes![index, present_key, validate_nonce, sign_request])
}
