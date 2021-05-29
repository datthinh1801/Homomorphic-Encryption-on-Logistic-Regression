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
}

int main()
{
    return 0;
}