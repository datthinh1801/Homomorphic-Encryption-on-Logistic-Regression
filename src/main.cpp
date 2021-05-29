#include "seal/seal.h"
#include "homomorphic.hpp"
#include <iostream>
#include <vector>
using namespace std;
using namespace seal;

int main()
{
    // Initialize a SEALContext object
    SEALContext context = SetupCKKS(16384);
    print_parameters(context);
    // Validate parameters
    cout << "Valid: " << context.parameter_error_message() << endl;
    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // Generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Plaintext plain;
    vector<double> input{0.0, 1.0, 2.0, 3.0};
    Encode(encoder, input, scale, plain);

    Ciphertext ciphertext = Encrypt(context, public_key, scale, plain);
    Ciphertext encrypted_result = Sigmoid(context, relin_keys, scale, ciphertext);
    Plaintext recover = Decrypt(context, secret_key, encrypted_result);
    Decode(encoder, recover, input);
    print_vector(input);

    return 0;
}