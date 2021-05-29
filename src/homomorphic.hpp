#include "seal/seal.h"
#include "helper.hpp"
#include <iostream>
#include <vector>
using namespace std;
using namespace seal;

SEALContext SetupCKKS(size_t poly_modulus_degree)
{
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 60}));
    return SEALContext(parms);
}

Ciphertext Encrypt(SEALContext &context, PublicKey &public_key, double &scale, Plaintext &plaintext)
{
    Encryptor encryptor(context, public_key);
    Ciphertext ciphertext;
    encryptor.encrypt(plaintext, ciphertext);
    return ciphertext;
}

Plaintext Decrypt(SEALContext &context, SecretKey &secret_key, Ciphertext &ciphertext)
{
    Decryptor decryptor(context, secret_key);
    Plaintext plaintext;
    decryptor.decrypt(ciphertext, plaintext);
    return plaintext;
}

void Encode(SEALContext &context, vector<double> &input, double &scale, Plaintext &output)
{
    CKKSEncoder encoder(context);
    encoder.encode(input, scale, output);
}

void Decode(SEALContext &context, Plaintext &input, vector<double> &output)
{
    CKKSEncoder encoder(context);
    encoder.decode(input, output);
}

void Encode(SEALContext &context, double input, double &scale, Plaintext &output)
{
    CKKSEncoder encoder(context);
    encoder.encode(input, scale, output);
}

Ciphertext Sigmoid(SEALContext &context, RelinKeys &relin_keys, double scale, Ciphertext &x_encrypted)
{
    Evaluator evaluator(context);

    // x_encrypted -> Level 3
    Ciphertext x_sq_encrypted;
    evaluator.square(x_encrypted, x_sq_encrypted);
    evaluator.relinearize_inplace(x_sq_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x_sq_encrypted);
    // x_sq_encrypted -> Level 2

    Ciphertext x_quad_encrypted;
    evaluator.square(x_sq_encrypted, x_quad_encrypted);
    evaluator.relinearize_inplace(x_quad_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x_quad_encrypted);
    // x_quad_encrypted -> Level 1

    Ciphertext x_encrypted_coeff5;
    Plaintext plain_coeff5;
    Encode(context, 0.002, scale, plain_coeff5);
    // plain_coef5 -> Level 3
    evaluator.multiply_plain(x_encrypted, plain_coeff5, x_encrypted_coeff5);
    // unnecessary to relinearize the result of 1 ciphertext and 1 plaintext
    // only necessary or both ciphertexts
    evaluator.rescale_to_next_inplace(x_encrypted_coeff5);
    // x_encrypted_coeff5 -> Level 2

    parms_id_type x_quad_encrypted_parms_id = x_quad_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x_encrypted_coeff5, x_quad_encrypted_parms_id);
    // x_encrypted_coef5 -> Level 1

    Ciphertext x_pow_5_encrypted_coeff5;
    evaluator.multiply(x_quad_encrypted, x_encrypted_coeff5, x_pow_5_encrypted_coeff5);
    evaluator.relinearize_inplace(x_pow_5_encrypted_coeff5, relin_keys);
    evaluator.rescale_to_next_inplace(x_pow_5_encrypted_coeff5);
    // x_pow_5_encrypted_coeff5 -> Level 0

    return x_pow_5_encrypted_coeff5;
}