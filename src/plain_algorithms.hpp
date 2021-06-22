#include <iostream>
#include <vector>
#include <cmath>
using namespace std;

double PlainVectorMultiplication(const vector<double> &sample, const vector<double> &weights)
{
    double product = 0;
    for (size_t i = 0; i < sample.size(); ++i)
    {
        product += sample[i] * weights[i];
    }
    return product;
}

double PlainSigmoid(const vector<double> &sample, const vector<double> &weights)
{
    double product = PlainVectorMultiplication(sample, weights);
    double sigmoid = 1.0 / (1 + exp(product * (-1)));
    return sigmoid;
}

double ComputeAccuracy(const vector<vector<double>> &features, const vector<double> &labels, const vector<double> &weights)
{
    vector<double> result(features.size());
    size_t correct = 0;

    for (size_t i = 0; i < features.size(); ++i)
    {
        result[i] = PlainSigmoid(features[i], weights);

        if (round(result[i]) == labels[i])
        {
            ++correct;
        }
    }

    return double(correct) / result.size();
}