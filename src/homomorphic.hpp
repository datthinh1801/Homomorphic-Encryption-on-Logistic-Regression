#include "seal/seal.h"
#include "helper.hpp"
#include <iostream>
#include <vector>
using namespace std;
using namespace seal;

SEALContext SetupCKKS()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 16384;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    try
    {
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 60}));
    }
    catch (exception e)
    {
        cout << e.what() << endl;
        exit(1);
    }
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

void Encode(SEALContext &context, vector<double> &input, double &scale, Plaintext &output)
{
    CKKSEncoder encoder(context);
    Encode(encoder, input, scale, output);
}

void Decode(SEALContext &context, Plaintext &input, vector<double> &output)
{
    CKKSEncoder encoder(context);
    Decode(encoder, input, output);
}

void Encode(SEALContext &context, double input, double &scale, Plaintext &output)
{
    CKKSEncoder encoder(context);
    Encode(encoder, input, scale, output);
}

// Perform sigmoid function on the x_encrypted (Level 5)
// The Ciphertext output will be a "spread" result (Level 2)
Ciphertext Sigmoid(SEALContext &context, RelinKeys &relin_keys, double scale, Ciphertext &x_encrypted)
{
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    ///////////////////////////////////////////////////////////////
    /*
                    [ COMPUTE 0.002x^5]
    */

    // ------------------------------------------------------- //
    // x_encrypted -> Level 5
    // compute x_encrypted ^ 2
    Ciphertext x_sq_encrypted;
    evaluator.square(x_encrypted, x_sq_encrypted);
    evaluator.relinearize_inplace(x_sq_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x_sq_encrypted);
    x_sq_encrypted.scale() = scale;
    // x_sq_encrypted -> Level 4

    // ------------------------------------------------------- //
    // x_sq_encrypted -> Level 4
    // compute x_encrypted ^ 4
    Ciphertext x_quad_encrypted;
    evaluator.square(x_sq_encrypted, x_quad_encrypted);
    evaluator.relinearize_inplace(x_quad_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x_quad_encrypted);
    x_quad_encrypted.scale() = scale;
    // x_quad_encrypted -> Level 3

    // ------------------------------------------------------- //
    // x_encrypted -> Level 5
    // compute 0.002 * x_encrypted
    Ciphertext x_encrypted_coeff5;
    Plaintext plain_coeff5;
    Encode(encoder, 0.002, scale, plain_coeff5);

    // plain_coeff_5 - Level 6
    // x_encrypted - Level 5
    // => mod switch plain_coeff_5 to level 5
    parms_id_type x_encrypted_parms_id = x_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(plain_coeff5, x_encrypted_parms_id);

    evaluator.multiply_plain(x_encrypted, plain_coeff5, x_encrypted_coeff5);
    // unnecessary to relinearize the result of 1 ciphertext and 1 plaintext
    // only necessary or both ciphertexts
    evaluator.rescale_to_next_inplace(x_encrypted_coeff5);
    x_encrypted_coeff5.scale() = scale;
    // x_encrypted_coeff5 -> Level 4

    // ------------------------------------------------------- //
    // x_encrypted_coeff5 -> Level 4
    // compute 0.002 * (x_encrypted ^ 5)

    // x_encrypted_coeff5 -> Level 4
    // x_quad_encrypted -> Level 3
    // => mod switch x_encrypted_coeff5 to level 3
    parms_id_type x_quad_encrypted_parms_id = x_quad_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x_encrypted_coeff5, x_quad_encrypted_parms_id);

    Ciphertext x_pow_5_encrypted_coeff5;
    evaluator.multiply(x_quad_encrypted, x_encrypted_coeff5, x_pow_5_encrypted_coeff5);
    evaluator.relinearize_inplace(x_pow_5_encrypted_coeff5, relin_keys);
    evaluator.rescale_to_next_inplace(x_pow_5_encrypted_coeff5);
    x_pow_5_encrypted_coeff5.scale() = scale;
    // x_pow_5_encrypted_coeff5 -> Level 2

    // save parms_id for later mod switch
    parms_id_type last_parms_id = x_pow_5_encrypted_coeff5.parms_id();
    // Level 2

    ///////////////////////////////////////////////////////////////
    /*
                        [COMPUTE 0.021x^3]
    */

    // ------------------------------------------------------- //
    // x_encrypted -> Level 5
    // compute 0.021 * x_encrypted
    Ciphertext x_encrypted_coeff3;
    Plaintext plain_coeff3;
    Encode(encoder, 0.021, scale, plain_coeff3);
    // plain_coeff3 -> Level 5

    evaluator.multiply_plain(x_encrypted, plain_coeff3, x_encrypted_coeff3);
    evaluator.rescale_to_next_inplace(x_encrypted_coeff3);
    x_encrypted_coeff3.scale() = scale;
    // x_encrypted_coeff3 -> Level 4

    // ------------------------------------------------------- //
    // x_encrypted_coeff3 -> Level 4
    // x_sq_encrypted -> Level 4
    // compute 0.021 * (x_encrypted ^ 3)
    Ciphertext x_pow_3_encrypted_coeff3;
    evaluator.multiply(x_sq_encrypted, x_encrypted_coeff3, x_pow_3_encrypted_coeff3);
    evaluator.relinearize_inplace(x_pow_3_encrypted_coeff3, relin_keys);
    evaluator.rescale_to_next_inplace(x_pow_3_encrypted_coeff3);
    x_pow_3_encrypted_coeff3.scale() = scale;
    // x_pow_3_encrypted_coeff3 -> Level 3

    evaluator.mod_switch_to_inplace(x_pow_3_encrypted_coeff3, last_parms_id);
    // x_pow_3_encrypted_coeff3 -> Level 2

    ///////////////////////////////////////////////////////////////
    /*
                        [COMPUTE 0.25x]
    */

    // ------------------------------------------------------- //
    // x_encrypted -> Level 5
    // compute 0.25 * x_encrypted
    Ciphertext x_encrypted_coeff1;
    Plaintext plain_coeff1;
    Encode(encoder, 0.25, scale, plain_coeff1);
    // plain_coeff1 -> Level 5

    evaluator.multiply_plain(x_encrypted, plain_coeff1, x_encrypted_coeff1);
    evaluator.rescale_to_next_inplace(x_encrypted_coeff1);
    x_encrypted_coeff1.scale() = scale;
    // x_encrypted_coeff1 -> Level 4

    evaluator.mod_switch_to_inplace(x_encrypted_coeff1, last_parms_id);
    // x_encrypted_coeff1 -> Level 2

    ///////////////////////////////////////////////////////////////
    /*
                        [COMPUTE FINAL RESULT]
    */

    Plaintext plain_coeff0;
    Encode(encoder, 0.5, scale, plain_coeff0);
    // plain_coeff0 -> Level 5

    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);
    // plain_coeff0 -> Level 2

    Ciphertext encrypted_final_result;
    // result = 0.5 + 0.25x
    evaluator.add_plain(x_encrypted_coeff1, plain_coeff0, encrypted_final_result);
    // result -= 0.021x^3
    evaluator.sub_inplace(encrypted_final_result, x_pow_3_encrypted_coeff3);
    // result += 0.002x^5
    evaluator.add_inplace(encrypted_final_result, x_pow_5_encrypted_coeff5);

    return encrypted_final_result;
}

/*
// Sum all elements of the given plaintext
Ciphertext Sum(SEALContext &context, GaloisKeys &galois_keys, const Ciphertext &x_encrypted, size_t slot_count)
{
    Evaluator evaluator(context);

    Ciphertext copied_x1 = x_encrypted;
    Ciphertext copied_x2 = x_encrypted;
    for (size_t i = 1; i < slot_count; ++i)
    {
        evaluator.rotate_vector_inplace(copied_x2, 1, galois_keys);
        evaluator.add_inplace(copied_x1, copied_x2);
    }
    return copied_x1;
}

// Perform vector multiplication between the x_encrypted (Level 6) and the weights_encrypted (Level 6)
// The Ciphertext output will be a "spread" sum of the multiplication result (Level 5)
Ciphertext VectorMultiplication(SEALContext &context, RelinKeys &relin_keys, GaloisKeys &galois_keys, const Ciphertext &x_encrypted, const Ciphertext &weights_encrypted, size_t slot_count)
{
    Evaluator evaluator(context);

    // x1 - Level 6
    // x2 - Level 6
    Ciphertext encrypted_product;
    evaluator.multiply(x_encrypted, weights_encrypted, encrypted_product);
    evaluator.relinearize_inplace(encrypted_product, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_product);
    // encrypted_product -> Level 5

    return Sum(context, galois_keys, encrypted_product, slot_count);
}
*/

// Perform partial derivative on the sigmoided_value of one single encrypted sample
// Ciphertext inputs:
// sigmoided_value  -> Level 2
// x_encrypted      -> Level 6
// y_encrypted      -> Leevl 6
// Ciphertext output:
// result           -> Level 1
Ciphertext PartialDerivative(SEALContext &context, RelinKeys &relin_keys, Ciphertext &sigmoided_value, const Ciphertext &x_encrypted, const Ciphertext &y_encrypted, double scale)
{
    // sigmoided_value  -> Level 2
    // x_encrypted      -> Level 5
    // y_encrypted      -> Level 5
    Evaluator evaluator(context);

    Ciphertext x = x_encrypted, y = y_encrypted;
    Ciphertext result = sigmoided_value;

    // modulus switch x_encrypted and y_encrypted to the same as sigmoided_value
    parms_id_type result_parms_id = result.parms_id();

    // Rescale all operands
    result.scale() = scale;
    x.scale() = scale;
    y.scale() = scale;

    evaluator.mod_switch_to_inplace(x, result_parms_id);
    // x -> Level 2

    evaluator.mod_switch_to_inplace(y, result_parms_id);
    // y -> Level 2

    // result = -sigmoided_value
    evaluator.negate_inplace(result);

    // result = y_encrypted - sigmoided_value
    evaluator.add_inplace(result, y);

    // result = (y_encrypted - sigmoided_value) * x_encrypted
    evaluator.multiply_inplace(result, x);
    evaluator.relinearize_inplace(result, relin_keys);
    evaluator.rescale_to_next_inplace(result);
    // result -> Level 1

    return result;
}

Ciphertext SumPartialDerivative(SEALContext &context, RelinKeys &relin_keys, const vector<Ciphertext> &derivatives)
{
    Evaluator evaluator(context);

    Ciphertext encrypted_sum = derivatives[0];
    for (size_t i = 1; i < derivatives.size(); ++i)
    {
        evaluator.add_inplace(encrypted_sum, derivatives[i]);
    }

    return encrypted_sum;
}

// This algorithm is only able to train 1 iteration at a time due to incompatible levels of operands at the end of the algorithm.
// This function return the new adjusted encrypted weights parameter.
Ciphertext Train(SEALContext &context, RelinKeys &relin_keys, GaloisKeys &galois_keys, double scale, const vector<Ciphertext> &encrypted_products,
                 const vector<Ciphertext> &samples, const vector<Ciphertext> &labels,
                 const Ciphertext &weight, const Ciphertext &learning_rate, size_t slot_count)
{
    Evaluator evaluator(context);

    // --------------------------------------------------------------------- //
    // Compute (learning_rate / m)
    Plaintext plain_m;
    Encode(context, 1.0 / samples.size(), scale, plain_m);

    Ciphertext learning_rate_mul_inv_m;
    evaluator.multiply_plain(learning_rate, plain_m, learning_rate_mul_inv_m);
    evaluator.relinearize_inplace(learning_rate_mul_inv_m, relin_keys);
    evaluator.rescale_to_next_inplace(learning_rate_mul_inv_m);
    learning_rate_mul_inv_m.scale() = scale;
    // learning_rate_mul_inv_m -> Level 4

    // --------------------------------------------------------------------- //
    // Privacy preserving logistic regression algorithm
    vector<Ciphertext> partial_derivatives;
    // Compute sigmoid values of all samples
    for (size_t i = 0; i < samples.size(); ++i)
    {
        // ----------------------------------------------------------------- //
        Ciphertext encrypted_sample_x_weights = encrypted_products[i];
        // encrypted_sample_x_weights -> Level 5

        // ----------------------------------------------------------------- //
        // Perform sigmoid function
        Ciphertext sigmoid = Sigmoid(context, relin_keys, scale, encrypted_sample_x_weights);
        sigmoid.scale() = scale;
        // sigmoid -> Level 2

        // ----------------------------------------------------------------- //
        // Compute the partial derivative of the weighted sample
        Ciphertext partial_derivative = PartialDerivative(context, relin_keys, sigmoid, samples[i], labels[i], scale);
        partial_derivative.scale() = scale;
        // partial_derivative -> Level 1

        partial_derivatives.push_back(partial_derivative);
    }

    // --------------------------------------------------------------------- //
    // Compute the sum of the partial derivatives
    Ciphertext encrypted_derivatives_sum = SumPartialDerivative(context, relin_keys, partial_derivatives);
    encrypted_derivatives_sum.scale() = scale;
    // encrypted_derivatives_sum -> Level 1

    // --------------------------------------------------------------------- //
    // Modulus switch learning_rate_mul_inv_m to level 1
    parms_id_type encrypted_derivatives_sum_parms_id = encrypted_derivatives_sum.parms_id();
    evaluator.mod_switch_to_inplace(learning_rate_mul_inv_m, encrypted_derivatives_sum_parms_id);
    // learning_rate_mul_inv_m -> Level 1

    // --------------------------------------------------------------------- //
    // compute learning_rate / m * sum_derivatives
    // result is called encrypted_weight_adjustment
    Ciphertext encrypted_weight_adjustment;
    evaluator.multiply(encrypted_derivatives_sum, learning_rate_mul_inv_m, encrypted_weight_adjustment);
    evaluator.relinearize_inplace(encrypted_weight_adjustment, relin_keys);
    evaluator.rescale_to_next_inplace(encrypted_weight_adjustment);
    encrypted_weight_adjustment.scale() = scale;
    // encrypted_weight_adjustment -> Level 0

    // --------------------------------------------------------------------- //
    // update new weights
    Ciphertext trained_weight = weight;
    // trained_weight -> Level 5
    // encrypted_weight_adjustment -> Level 0
    // modulus switch trained_weight to level 0
    parms_id_type encrypted_weight_adjustment_parms_id = encrypted_weight_adjustment.parms_id();
    evaluator.mod_switch_to_inplace(trained_weight, encrypted_weight_adjustment_parms_id);
    // trained_weight -> Level 0

    // Update weight
    evaluator.add_inplace(trained_weight, encrypted_weight_adjustment);

    return trained_weight;
}
