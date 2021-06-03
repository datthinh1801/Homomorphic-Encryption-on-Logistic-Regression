#include <iostream>
#include <vector>

#include "seal/seal.h"
#include "homomorphic.hpp"
#include "data_preprocessing.hpp"
#include "plain_algorithms.hpp"
using namespace std;
using namespace seal;

#define MAX_ITER 10

int main()
{
    /*
    [DATA PREPROCESSING]
    */
    // Read data from csv file
    // auto dataset = ReadDatasetFromCSV(".\\dataset\\train_data.csv");
    auto dataset = ReadDatasetFromCSV(".\\dataset\\one_line.csv");
    if (dataset.back().size() == 0)
    {
        dataset.pop_back();
    }

    auto labels = ExtractLabel(dataset, 1);
    auto features = dataset;
    double learning_rate = 0.1;
    int iteration = ReadCheckpointFromFile(".\\weights\\iteration.txt");
    vector<double> weights(features[0].size(), 0);
    if (iteration > 1)
    {
        weights = ReadWeightsFromCSV(".\\weights\\weights.csv");
    }

    /*
    [HOMOMORPHIC INITIALIZATION]
    */
    // Initialize a SEALContext object
    SEALContext context = SetupCKKS();
    print_parameters(context);
    // Validate parameters
    cout << "Are the parameters valid? " << context.parameter_error_message() << endl;
    double scale = pow(2.0, 20);
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

    /*
    [DATA PREPARATION FOR HOMOMORPHIC TRAINING]
    */
    // Encrypt labels
    vector<Ciphertext> encrypted_labels;
    for (int i = 0; i < labels.size(); ++i)
    {
        Plaintext plain_label;
        Encode(encoder, labels[i], scale, plain_label);
        Ciphertext encrypted_label = Encrypt(context, public_key, scale, plain_label);
        encrypted_labels.push_back(encrypted_label);
    }

    // Encrypt learning rate
    Plaintext plain_learning_rate;
    Encode(encoder, learning_rate, scale, plain_learning_rate);
    Ciphertext encrypted_learning_rate = Encrypt(context, public_key, scale, plain_learning_rate);

    /*
    [HOMOMORPHICALLY TRAIN A LOGISTIC REGRESS MODEL]
    */
    int total_start = clock();
    for (iteration; iteration <= MAX_ITER; ++iteration)
    {
        // Encrypt product of features and weights
        vector<Ciphertext> encrypted_features;
        for (int i = 0; i < features.size(); ++i)
        {
            double product = PlainVectorMultiplication(features[i], weights);
            Plaintext plain_product;
            Encode(encoder, product, scale, plain_product);
            Ciphertext encrypted_product = Encrypt(context, public_key, scale, plain_product);
            encrypted_features.push_back(encrypted_product);
        }

        // Encrypt weights
        Plaintext plain_weights;
        Encode(encoder, weights, scale, plain_weights);
        Ciphertext encrypted_weights = Encrypt(context, public_key, scale, plain_weights);

        // Start training
        unsigned long iteration_start = clock();
        cout << "Iteration #" << iteration << "...\t";

        // Homomorphically train
        Ciphertext encrypted_trained_weights = Train(context, relin_keys, galois_keys, scale, encrypted_features, encrypted_labels, encrypted_weights,
                                                     encrypted_learning_rate, slot_count);

        // End training
        unsigned long iteration_end = clock();

        // Decrypt and update new weights
        Plaintext plain_trained_weights = Decrypt(context, secret_key, encrypted_trained_weights);
        Decode(context, plain_trained_weights, weights);

        cout << "Training time: " << (iteration_end - iteration_start) / CLOCKS_PER_SEC << "s\t";
        cout << "Train accuracy: " << ReportAccuracy(features, labels, weights) << endl;

        WriteCheckpointToFile(".\\weights\\iteration.txt", iteration);
        WriteWeightsToCSV(".\\weights\\weights.csv", weights);
    }

    int total_end = clock();
    cout << "Trained weights:" << endl;
    print_vector(weights);
    cout << "Training time: " << (total_end - total_start) / CLOCKS_PER_SEC << "s" << endl;

    return 0;
}