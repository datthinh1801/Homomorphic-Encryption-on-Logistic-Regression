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
    // 5 primes to support 4 level of multiplicative depth
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 60}));
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

void Encode(CKKSEncoder &encoder, vector<double> &input, double &scale, Plaintext &output)
{
    encoder.encode(input, scale, output);
}

void Decode(CKKSEncoder &encoder, Plaintext &input, vector<double> &output)
{
    encoder.decode(input, output);
}

void Encode(CKKSEncoder &encoder, double input, double &scale, Plaintext &output)
{
    encoder.encode(input, scale, output);
}

// Perform sigmoid function on the x_encrypted (Level 5)
// The Ciphertext output will be a "spread" result (Level 2)
Ciphertext Sigmoid(SEALContext &context, RelinKeys &relin_keys, double scale, Ciphertext &x_encrypted)
{
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    /*
                    [ COMPUTE 0.002x^5]
    */

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
    Encode(encoder, 0.002, scale, plain_coeff5);
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

    parms_id_type last_parms_id = x_pow_5_encrypted_coeff5.parms_id();

    /*
                        [COMPUTE 0.021x^3]
    */

    Ciphertext x_encrypted_coeff3;
    Plaintext plain_coeff3;
    Encode(encoder, 0.021, scale, plain_coeff3);
    // plain_coeff3 -> Level 3

    evaluator.multiply_plain(x_encrypted, plain_coeff3, x_encrypted_coeff3);
    evaluator.rescale_to_next_inplace(x_encrypted_coeff3);
    // x_encrypted_coeff3 -> Level 2

    Ciphertext x_pow_3_encrypted_coeff3;
    evaluator.multiply(x_sq_encrypted, x_encrypted_coeff3, x_pow_3_encrypted_coeff3);
    evaluator.relinearize_inplace(x_pow_3_encrypted_coeff3, relin_keys);
    evaluator.rescale_to_next_inplace(x_pow_3_encrypted_coeff3);
    // x_pow_3_encrypted_coeff3 -> Level 1

    evaluator.mod_switch_to_inplace(x_pow_3_encrypted_coeff3, last_parms_id);
    // x_pow_3_encrypted_coeff3 -> Level 0

    /*
                        [COMPUTE 0.25x]
    */

    Ciphertext x_encrypted_coeff1;
    Plaintext plain_coeff1;
    Encode(encoder, 0.25, scale, plain_coeff1);
    // plain_coeff1 -> Level 3

    evaluator.multiply_plain(x_encrypted, plain_coeff1, x_encrypted_coeff1);
    evaluator.rescale_to_next_inplace(x_encrypted_coeff1);
    // x_encrypted_coeff1 -> Level 2

    evaluator.mod_switch_to_inplace(x_encrypted_coeff1, last_parms_id);
    // x_encrypted_coeff1 -> Level 0

    /*
                        [COMPUTE FINAL RESULT]
    */

    Plaintext plain_coeff0;
    Encode(encoder, 0.5, scale, plain_coeff0);
    // plain_coeff0 -> Level 3

    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);
    // plain_coeff0 -> Level 0

    // Set scales of all coefficients to the same scale
    x_pow_5_encrypted_coeff5.scale() = scale;
    x_pow_3_encrypted_coeff3.scale() = scale;
    x_encrypted_coeff1.scale() = scale;
    plain_coeff0.scale() = scale;

    Ciphertext encrypted_final_result;
    // result = 0.5 + 0.25x
    evaluator.add_plain(x_encrypted_coeff1, plain_coeff0, encrypted_final_result);
    // result -= 0.021x^3
    evaluator.sub_inplace(encrypted_final_result, x_pow_3_encrypted_coeff3);
    // result += 0.002x^5
    evaluator.add_inplace(encrypted_final_result, x_pow_5_encrypted_coeff5);

    return encrypted_final_result;
}

Ciphertext Sum(SEALContext &context, GaloisKeys &galois_kes, const Ciphertext &x1, const Ciphertext &x2, size_t slot_count)
{
    Evaluator evaluator(context);

    Ciphertext copied_x1 = x1;
    Ciphertext copied_x2 = x2;
    for (size_t i = 1; i < slot_count; ++i)
    {
        evaluator.rotate_vector_inplace(copied_x2, 1, galois_kes);
        evaluator.add_inplace(copied_x1, copied_x2);
    }
    return copied_x1;
}

// Perform vector multiplication between the x_encrypted (Level 6) and the weights_encrypted (Level 6)
// The Ciphertext output will be a "spread" sum of the multiplication result (Level 5)
Ciphertext VectorMultiplication(SEALContext &context, RelinKeys &relin_keys, GaloisKeys &galois_keys, Ciphertext &x_encrypted, Ciphertext &weights_encrypted, size_t slot_count)
{
    Evaluator evaluator(context);

    // x1 - Level 6
    // x2 - Level 6
    Ciphertext encrypted_product;
    evaluator.multiply(x_encrypted, weights_encrypted, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);
    // encrypted_product -> Level 5

    return Sum(context, galois_keys, encrypted_product, encrypted_product, slot_count);
}

// Perform partial derivative on the sigmoided_value of one single encrypted sample
// Ciphertext inputs:
// sigmoided_value  -> Level 2
// x_encrypted      -> Level 6
// y_encrypted      -> Leevl 6
// Ciphertext output:
// result           -> Level 1
Ciphertext PartialDerivative(SEALContext &context, RelinKeys &relin_keys, Ciphertext &sigmoided_value, const Ciphertext &x_encrypted, const Ciphertext &y_encrypted)
{
    // sigmoided_value  -> Level 2
    // x_encrypted      -> Level 6
    // y_encrypted      -> Level 6
    Evaluator evaluator(context);

    // modulus switch x_encrypted and y_encrypted to the same as sigmoided_value
    parms_id_type sigmoided_value_parms_id = sigmoided_value.parms_id();

    Ciphertext x = x_encrypted, y = y_encrypted;
    evaluator.mod_switch_to_inplace(x, sigmoided_value_parms_id);
    // x -> Level 2

    evaluator.mod_switch_to_inplace(y, sigmoided_value_parms_id);
    // y -> Level 2

    Ciphertext result = sigmoided_value;

    // result = -sigmoided_value
    evaluator.negate(sigmoided_value, result);

    // result = y_encrypted - sigmoided_value
    evaluator.add_inplace(result, y);

    // result = (y_encrypted - sigmoided_value) * x_encrypted
    evaluator.multiply_inplace(result, x);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);
    // result -> Level 1

    return result;
}

// Ciphertext Train(SEALContext &context, RelinKeys &relin_keys, double scale, vector<Ciphertext> &sample, Ciphertext &weight)
// {
// }