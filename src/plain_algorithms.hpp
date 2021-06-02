#include <iostream>
#include <vector>
#include <cmath>
using namespace std;

double PlainVectorMultiplication(const vector<double> &sample, const vector<double> &weights)
{
    vector<double> element_mul(sample.size(), 0);
    for (size_t i = 0; i < sample.size(); ++i)
    {
        element_mul[i] = sample[i] * weights[i];
    }

    double sum = 0;
    for (size_t i = 0; i < element_mul.size(); ++i)
    {
        sum += element_mul[i];
    }
    return sum;
}

double PlainSigmoid(const vector<double> &sample, const vector<double> &weights)
{
    double mul_result = PlainVectorMultiplication(sample, weights);
    double sigmoid = 1.0 / (1 + exp(mul_result * (-1)));
    return sigmoid;
}

double ReportAccuracy(const vector<vector<double>> &features, const vector<double> &labels, const vector<double> &weights)
{
    vector<double> result;
    size_t correct = 0;

    for (size_t i = 0; i < features.size(); ++i)
    {
        double prediction = PlainSigmoid(features[i], weights);
        result.push_back(round(prediction));

        if (result.back() == labels[i])
        {
            ++correct;
        }
    }

    return (1.0 * correct) / result.size();
}