pub mod kzg;
pub mod asvc;
pub mod utils;

use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;
use alloy::eips::eip4844::BYTES_PER_BLOB;
use alloy::primitives::FixedBytes;
use rand::seq::IteratorRandom;
use c_kzg::{Blob, Bytes32, Error, KzgCommitment, KzgProof, KzgSettings};
use std::str;
use alloy::hex::ToHex;
use crate::utils::evaluate;

#[tokio::main]
async fn main() {
    // trusted setup ceremony
    let trusted_setup = KzgSettings::load_trusted_setup_file(Path::new("./src/trusted_setup.txt"))
        .expect("Error loading trusted setup file");

    // hex of the blob data from the block 630872 of L2
    // https://voyager.online/block/0x3333f2f6b32776ac031e7ed373858c656d6d1040e47b73c94e762e6ed4cedf3 (L2)
    // https://etherscan.io/tx/0x6b9fc547764a5d6e4451b5236b92e74c70800250f00fc1974fc0a75a459dc12e (L1)
    let file_path = "./src/hex_block_630872.txt";

    // generate polynomial and commit it
    let file = File::open(file_path).expect("Unable to load the file for hex");
    let reader = io::BufReader::new(file);
    let mut data = String::new();
    for line in reader.lines().map_while(Result::ok) {
        data.push_str(&line);
    }

    let data_v8 = hex_string_to_u8_vec(&data).expect("error creating hex string from data");
    let x_0 = "0x1cab333ee4c0b03ba79bb51bc537545e3aef820434c0c06e00235dd9ccdafdf";
    let x_0_array = string_to_fixed_array(x_0).unwrap();

    println!("x_0_array : {:?}",x_0_array);

    let (_sidecar_blobs, sidecar_commitments, sidecar_proofs) =
        prepare_sidecar(&[data_v8], &trusted_setup, x_0_array).await.expect("Error creating the sidecar blobs");
}

fn hex_string_to_u8_vec(hex_str: &str) -> Result<Vec<u8>, String> {
    // Remove any spaces or non-hex characters from the input string
    let cleaned_str: String = hex_str.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    // Convert the cleaned hex string to a Vec<u8>
    let mut result = Vec::new();
    for chunk in cleaned_str.as_bytes().chunks(2) {
        if let Ok(byte_val) = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16) {
            result.push(byte_val);
        } else {
            return Err(format!("Error parsing hex string: {}", cleaned_str));
        }
    }
    println!("length of vec<u8>: {}", result.len());
    Ok(result)
}

async fn prepare_sidecar(
    state_diff: &[Vec<u8>],
    trusted_setup: &KzgSettings,
    x_0_point: [u8; 32]
) -> Result<(Vec<FixedBytes<131072>>, Vec<FixedBytes<48>>, Vec<FixedBytes<48>>), Error> {
    let mut sidecar_blobs = vec![];
    let mut sidecar_commitments = vec![];
    let mut sidecar_proofs = vec![];

    for blob_data in state_diff {
        let mut fixed_size_blob: [u8; BYTES_PER_BLOB] = [0; BYTES_PER_BLOB];
        fixed_size_blob.copy_from_slice(blob_data.as_slice());

        let blob = Blob::new(fixed_size_blob);
        println!("blob : {:?}", blob.len());
        println!("bytes x_0 = z : {:?}", &Bytes32::from(x_0_point));
        println!("trusted_setup : {:?}",trusted_setup);
        let proof_kzg_output_final = KzgProof::compute_kzg_proof(&blob, &Bytes32::from(x_0_point), trusted_setup).unwrap();
        println!("KZG Proof (C' & C) = π: {:?}", proof_kzg_output_final.0.as_hex_string());
        let string_eval: String = String::from_utf8_lossy(proof_kzg_output_final.1.as_ref()).to_string().encode_hex();
        println!("Eval(x_0) = y : {:?}", proof_kzg_output_final.1);
        println!("Eval(x_0) = y : {:?}", string_eval);

        let commitment = KzgCommitment::blob_to_kzg_commitment(&blob, trusted_setup)?;
        let proof = KzgProof::compute_blob_kzg_proof(&blob, &commitment.to_bytes(), trusted_setup)?;
        let eval = KzgProof::verify_kzg_proof(&commitment.to_bytes(),&Bytes32::from(x_0_point), &proof_kzg_output_final.1, &proof.to_bytes(), trusted_setup).unwrap();
        println!("Verified : {:?}", eval);

        sidecar_blobs.push(FixedBytes::new(fixed_size_blob));
        sidecar_commitments.push(FixedBytes::new(commitment.to_bytes().into_inner()));
        sidecar_proofs.push(FixedBytes::new(proof.to_bytes().into_inner()));

    }

    println!("KZG Proof (C) : {:?}", sidecar_proofs[0]);
    println!("KZG Commitment (C) : {:?}", sidecar_commitments[0]);

    Ok((sidecar_blobs, sidecar_commitments, sidecar_proofs))
}

fn string_to_fixed_array(s: &str) -> Result<[u8; 32], String> {
    let bytes = s.as_bytes(); // Convert the string to bytes

    if bytes.len() > 32 {
        // If the string is too long, we truncate it
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[0..32]);
        Ok(array)
    } else {
        // If the string is too short, we pad it with zeros
        let mut array = [0u8; 32];
        // Copy the bytes into the start of the array
        for (i, &byte) in bytes.iter().enumerate() {
            array[i] = byte;
        }
        Ok(array)
    }
}

// Expected Eval : 0x6566495cc11710abda13aa0f6571d7d92955d75df7ec82c002d5235ed3f199c1
// Expected Proof : 0xa168b317e7c44691ee1932bd12fc6ac22182277e8fc5cd4cd21adc0831c33b1359aa5171bba529c69dcfe6224b220f8f
// Generate Proof : 0xa1df04914128d896f85648ce2a5d6515bec8b5ec9b54e69cbc1ec194b1c68b91f9b3b649227176c1f42414af7cf94ae9