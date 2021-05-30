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

    // sample 1
    Plaintext plain_input;
    vector<double> input1{0.0, 1.0, 2.0, 3.0, 4.0, 5.0};
    Encode(encoder, input1, scale, plain_input);
    Ciphertext encrypted_input = Encrypt(context, public_key, scale, plain_input);

    vector<Ciphertext> encrypted_samples;
    encrypted_samples.push_back(encrypted_input);

    // sample 2
    vector<double> input2{0.0, 1.0, 0.0, 3.0, 1.0, 3.0};
    Encode(encoder, input2, scale, plain_input);
    encrypted_input = Encrypt(context, public_key, scale, plain_input);
    encrypted_samples.push_back(encrypted_input);

    // labels
    double label = 1.0;
    Plaintext plain_label;
    Encode(encoder, label, scale, plain_label);
    Ciphertext encrypted_label = Encrypt(context, public_key, scale, plain_label);

    vector<Ciphertext> encrypted_labels;
    encrypted_labels.push_back(encrypted_label);

    label = 0.0;
    Encode(encoder, label, scale, plain_label);
    encrypted_label = Encrypt(context, public_key, scale, plain_label);
    encrypted_labels.push_back(encrypted_label);

    // weight
    Plaintext plain_weight;
    vector<double> weights(5, 0);
    Encode(encoder, weights, scale, plain_weight);
    Ciphertext encrypted_weights = Encrypt(context, public_key, scale, plain_weight);

    // learning rate
    double learning_rate = 0.5;
    Plaintext plain_learning_rate;
    Encode(encoder, learning_rate, scale, plain_learning_rate);
    Ciphertext encrypted_learning_rate = Encrypt(context, public_key, scale, plain_learning_rate);

    // train
    Ciphertext encrypted_trained_weights = Train(context, relin_keys, galois_keys, scale, encrypted_samples, encrypted_labels, encrypted_weights, encrypted_learning_rate, slot_count);
    Plaintext plain_trained_weights = Decrypt(context, secret_key, encrypted_trained_weights);
    vector<double> trained_weights;
    Decode(context, plain_trained_weights, trained_weights);
    print_vector(trained_weights, 5, 7);

    return 0;
}