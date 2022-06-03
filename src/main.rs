extern crate rand;
use bip39::{Mnemonic, Language};
use secp256k1::{Secp256k1, KeyPair, PublicKey};
use tiny_keccak::keccak256;
use web3::types::Address;
use rustc_hex::ToHex;
use tiny_hderive::bip32::ExtendedPrivKey;
use tiny_hderive::bip44::DerivationPath;
use std::str::FromStr;
use std::io::Write;

// Function to make the wallet address from the public key
pub fn public_key_address_generator(public_key: &PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    Address::from_slice(&hash[12..])
}

fn main() {
    let mut file = std::fs::File::create("wallets.txt").expect("create failed");

    // Generate the mnemonic
    let mut rng = rand::thread_rng();
    let mnemo = Mnemonic::generate_in_with(&mut rng, Language::English, 12).unwrap();
    let englishwords = Mnemonic::to_string(&mnemo);
    let mut output = format!("\nThe mnemonic words are = {:?}", &englishwords);
    file.write_all(output.as_bytes()).expect("write failed");
        
    // Make the seed for derivation and for the hex
    let seed = Mnemonic::to_seed(&mnemo,"");
    let bip39_seed: String = seed.to_hex();
    output = format!("\n\nThe BIP39 seed is = {}\n \n \n",bip39_seed);
    file.write_all(output.as_bytes()).expect("write failed");
    file.write_all("------------------------------------------------------------------------------------".as_bytes()).expect("write failed");
    let secp = Secp256k1::new();

    // Set here how many wallet you want for the same mnemonic
    // Default 10 000
    for i in 0..10000 {
        let derive_path_str = format!("m/44'/60'/0'/0/{i}");
        let derive_path = DerivationPath::from_str(&derive_path_str).unwrap();
        let derived = ExtendedPrivKey::derive(&seed, derive_path).unwrap();
        let keypair= KeyPair::from_seckey_slice(&secp, &derived.secret()).unwrap();
        let public_key = PublicKey::from_keypair(&keypair);
        let public_address = public_key_address_generator(&public_key);
        let public_key_0x = public_key.to_string();
        let number_shift = i + 1;
        output = format!("\n\nPublic key {number_shift} = 0x{} \n\nAddress    {number_shift} = {:?}\nSecret key {number_shift} = 0x{}\n\n------------------------------------------------------------------------------------", public_key_0x, public_address, keypair.display_secret());
        file.write_all(output.as_bytes()).expect("write failed");
    }
    println!("wallets.txt created successfully!")
}
