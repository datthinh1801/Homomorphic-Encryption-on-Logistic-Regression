#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
using namespace std;

vector<vector<double>> ReadDatasetFromCSV(string filename)
{
    fstream fin;
    fin.open(filename, ios::in);

    vector<double> row;
    vector<vector<double>> dataset;
    string line, word;
    double value;

    // get rid of the header row
    getline(fin, line);
    while (fin.good())
    {
        row.clear();

        // Add bias
        row.push_back(1);

        // read 1 line
        getline(fin, line);

        // put the line to stream
        stringstream ssline(line);

        // read one field at a time
        while (getline(ssline, word, ','))
        {
            stringstream ssword(word);

            // convert the value from string to double
            ssword >> value;
            row.push_back(value);
        }

        dataset.push_back(row);
    }
    fin.close();
    return dataset;
}

// Write to a csv file
// If the file exists, its contents will be overwritten
// Otherwise, create a new file and write to it
void WriteWeightsToCSV(string filename, const vector<double> &data)
{
    fstream fout;
    fout.open(filename, ios::out);

    for (int i = 0; i < data.size(); ++i)
    {
        fout << data[i];
        if (i < data.size() - 1)
        {
            fout << ",";
        }
    }
    fout.close();
}

vector<double> ReadWeightsFromCSV(string filename)
{
    fstream fin;
    fin.open(filename, ios::in);

    vector<double> weights;
    string line, word;
    double value;

    while (fin.good())
    {
        getline(fin, line);
        stringstream ssline(line);
        while (getline(ssline, word, ','))
        {
            stringstream ssword(word);
            ssword >> value;
            weights.push_back(value);
        }
    }
    return weights;
}

int ReadCheckpointFromFile(string filename)
{
    fstream fin;
    fin.open(filename, ios::in);

    int saved_iteration;
    fin >> saved_iteration;
    fin.close();
    return saved_iteration;
}

void WriteCheckpointToFile(string filename, int iteration)
{
    fstream fout;
    fout.open(filename, ios::out);
    fout << iteration;
    fout.close();
}

vector<double> ExtractLabel(vector<vector<double>> &dataset, int col_idx)
{
    vector<double> labels;
    for (int i = 0; i < dataset.size(); ++i)
    {
        labels.push_back(dataset[i][col_idx]);
        dataset[i].erase(dataset[i].begin() + col_idx);
    }
    return labels;
}
