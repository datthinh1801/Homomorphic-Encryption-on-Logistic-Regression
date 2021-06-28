#include <iostream>
#include <vector>
#include <random>

#include "seal/seal.h"
#include "homomorphic.hpp"
#include "data_preprocessing.hpp"
#include "plain_algorithms.hpp"
using namespace std;
using namespace seal;

#define MAX_ITER 10

int main()
{
    srand(time(0));
    /*
    [DATA PREPROCESSING]
    */
    // Read data from csv file
    auto train_features = ReadDatasetFromCSV(".\\dataset\\diabetes_normalized.csv");
    if (train_features.back().size() == 0)
    {
        train_features.pop_back();
    }

    auto labels = ExtractLabel(train_features, 9);
    double learning_rate = 0.01;

    int iteration = ReadCheckpointFromFile(".\\weights\\iteration.txt");
    vector<double> weights(train_features[0].size(), rand());
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
    cout << endl;

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

    /*
    [DATA PREPARATION FOR HOMOMORPHIC TRAINING]
    */
    // Encrypt features
    vector<Ciphertext> encrypted_features;
    for (int i = 0; i < train_features.size(); ++i)
    {
        Plaintext plain_feature;
        Encode(encoder, train_features[i], scale, plain_feature);
        Ciphertext encrypted_feature = Encrypt(context, public_key, scale, plain_feature);
        encrypted_features.push_back((encrypted_feature));
    }

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
    double best_accuracy = 0;
    for (iteration; iteration <= MAX_ITER; ++iteration)
    {
        cout << "Iteration #" << iteration << "...\t\t";
        // Encrypt product of features and weights
        vector<Ciphertext> encrypted_products;
        for (int i = 0; i < train_features.size(); ++i)
        {
            double product = PlainVectorMultiplication(train_features[i], weights);
            Plaintext plain_product;
            Encode(encoder, product, scale, plain_product);
            Ciphertext encrypted_product = Encrypt(context, public_key, scale, plain_product);
            encrypted_products.push_back(encrypted_product);
        }

        // Encrypt weights
        Plaintext plain_weights;
        Encode(encoder, weights, scale, plain_weights);
        Ciphertext encrypted_weights = Encrypt(context, public_key, scale, plain_weights);

        // Start training
        unsigned long iteration_start = clock();

        // Homomorphically train
        Ciphertext encrypted_trained_weights = Train(context, relin_keys, galois_keys, scale, encrypted_products, encrypted_features, encrypted_labels, encrypted_weights,
                                                     encrypted_learning_rate, slot_count);

        // End training
        unsigned long iteration_end = clock();

        // Decrypt and update new weights in place
        Plaintext plain_trained_weights = Decrypt(context, secret_key, encrypted_trained_weights);
        Decode(context, plain_trained_weights, weights);
        weights.resize(train_features[0].size());

        cout << "Training time: " << (iteration_end - iteration_start) / CLOCKS_PER_SEC << "s\t\t";
        double train_accuracy = ComputeAccuracy(train_features, labels, weights);
        cout << "Train accuracy: " << train_accuracy << endl;

        if (train_accuracy > best_accuracy)
        {
            best_accuracy = train_accuracy;
            WriteWeightsToCSV(".\\weights\\best_weights.csv", weights);
        }

        WriteCheckpointToFile(".\\weights\\iteration.txt", iteration);
        WriteWeightsToCSV(".\\weights\\weights.csv", weights);
    }
    weights = ReadWeightsFromCSV(".\\weights\\best_weights.csv");
    cout << "Best weights:" << endl;
    print_vector(weights);
    cout << "Highest accuracy: " << ComputeAccuracy(train_features, labels, weights) << endl;

    return 0;
}