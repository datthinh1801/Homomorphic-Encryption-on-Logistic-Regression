#include "seal/seal.h"
#include "helper.hpp"
#include <iostream>
using namespace std;
using namespace seal;

void bfv_basics()
{
    EncryptionParameters parms(scheme_type::bfv);

    /*
    Set polynomial modulus.
    Recommended values are 1024, 2048, 4096, 8192, 16384, 32768, etc.
    Any value smaller than 4096 will restrict encrypted computation.
    */
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    /*
    Larger coeff_modulus implies a larger noise budget.

        +----------------------------------------------------+
        | poly_modulus_degree | max coeff_modulus bit-length |
        +---------------------+------------------------------+
        | 1024                | 27                           |
        | 2048                | 54                           |
        | 4096                | 109                          |
        | 8192                | 218                          |
        | 16384               | 438                          |
        | 32768               | 881                          |
        +---------------------+------------------------------+

    These numbers can be obtained from the function:
        CoeffiModulus::MaxBitcount(poly_modulus_degree)
    */

    // Helper function to select coeff_modulus:
    //      CoeffModulus::BFVDefault(poly_modulus_degree)
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // Set plain modulus
    parms.set_plain_modulus(1024);

    // Create a SEALContext object.
    SEALContext context(parms);

    cout << "Encryption parameters:" << endl;
    print_parameters(context);

    // Validate parameters
    cout << "Encryption parameters' validation: " << context.parameter_error_message() << endl;

    // Generate key
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys reline_keys;
    keygen.create_relin_keys(reline_keys);

    // Create encryptor, decryptor, and evaluator
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);

    // Calculate x^2 homomorphically
    int x = 3;
    Plaintext x_plain(to_string(x));

    // Encrypt x
    cout << "Encrypt x..." << endl;
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);

    // Size of a ciphertext is the number of polynomials.
    // The size of a freshly encrypted ciphertext is alwasy 2.
    cout << "Size of freshly encrypted x: " << x_encrypted.size() << endl;

    // Examine the initial noise budget.
    cout << "Initial noise budget of x: " << decryptor.invariant_noise_budget(x_encrypted) << " bits." << endl;

    // Decrypt x
    cout << "Decrypt x: ";
    Plaintext x_decrypted;
    decryptor.decrypt(x_encrypted, x_decrypted);
    cout << "0x" << x_decrypted.to_string() << endl;

    cout << "----------------------------------------------" << endl;

    cout << "Compute x^2." << endl;
    Ciphertext x_sq;
    evaluator.square(x_encrypted, x_sq);

    cout << "Size of x_sq: " << x_sq.size() << endl;
    cout << "Noise budget of x_sq: " << decryptor.invariant_noise_budget(x_sq) << " bits." << endl;

    cout << "Decrypt the result: ";
    Plaintext decrypted_result;
    decryptor.decrypt(x_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << endl;

    cout << "-----------------------------------------------" << endl;
    cout << "Compute x^2 with relinearization." << endl;
    evaluator.square(x_encrypted, x_sq);
    evaluator.relinearize_inplace(x_sq, reline_keys);
    cout << "Size of x_sq: " << x_sq.size() << endl;
    cout << "Noise budget of x_sq: " << decryptor.invariant_noise_budget(x_sq) << " bits." << endl;

    cout << "Decrypt the result: ";
    decryptor.decrypt(x_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << endl;
}

void encoders()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40, 40}));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "# slots: " << slot_count << endl;

    vector<double> input{0.0, 1.1, 2.2, 3.3};
    cout << "Input vector:" << endl;
    print_vector(input);

    Plaintext plain;
    // scale mustn't be too close to coeff_modulus
    double scale = pow(2.0, 30);
    encoder.encode(input, scale, plain);

    vector<double> output;
    cout << "Decode input vector:" << endl;
    encoder.decode(plain, output);
    print_vector(output);

    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    evaluator.square_inplace(encrypted);
    evaluator.relinearize_inplace(encrypted, relin_keys);

    cout << "Scale in squared input: " << encrypted.scale() << " (" << log2(encrypted.scale()) << " bits)" << endl;

    decryptor.decrypt(encrypted, plain);
    encoder.decode(plain, output);
    cout << "Result vector:" << endl;
    print_vector(output);
}

void ckks()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    // scale and in-the-middle primes should be close to each other
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "# slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (slot_count - 1);
    for (size_t i = 0; i < slot_count; ++i)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector:" << endl;
    print_vector(input, 3, 7);

    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159264, scale, plain_coeff3);
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext x3_encrypted;
    evaluator.square(x1_encrypted, x3_encrypted);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "Scale of x^2 before rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;

    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "Scale of x^2 after rescale: " << log2(x3_encrypted.scale()) << " bits" << endl;
    // x3_encrypted - level 1

    // only need to relinearize multiplication between input ciphertexts
    // multiplication between input ciphertext and plaintext is not necessary
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    // x1_encrypted_coeff3 - level 1

    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    evaluator.rescale_to_next_inplace(x3_encrypted);
    // x3_encrypted - level 0

    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    evaluator.rescale_to_next_inplace(x1_encrypted);
    // x1_encrypted - level 1

    cout << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Exact scale in PI * x * x^2: " << x3_encrypted.scale() << endl;
    cout << "Exact scale in 0.4 * x: " << x1_encrypted.scale() << endl;
    cout << "Exact scale in 1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "Exact scale in PI * x * x^3: " << x3_encrypted.scale() << endl;
    cout << "Exact scale in 0.4 * x: " << x1_encrypted.scale() << endl;
    cout << "Exact scale in 1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4) * x + 1);
    }
    print_vector(true_result, 3, 7);

    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Result:" << endl;
    print_vector(result, 3, 7);
}

void rotation()
{
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {40, 40, 40, 40, 40}));

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    size_t slot_count = encoder.slot_count();
    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (slot_count - 1);
    for (size_t i = 0; i < slot_count; ++i)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector:" << endl;
    print_vector(input, 3, 7);

    double scale = pow(2.0, 50);

    Plaintext plain;
    encoder.encode(input, scale, plain);
    Ciphertext encrypted;
    encryptor.encrypt(plain, encrypted);

    Ciphertext rotated;
    evaluator.rotate_vector(encrypted, 2, galois_keys, rotated);
    decryptor.decrypt(rotated, plain);
    vector<double> result;
    encoder.decode(plain, result);
    print_vector(result, 3, 7);
}

int main()
{
    rotation();
    return 0;
}