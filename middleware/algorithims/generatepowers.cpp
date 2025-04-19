#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <cmath>
#include <limits>
using namespace std;
#define int unsigned long long

int32_t main() {
    const int NUM_POWERS = 1e6;
    const int BASE = 128;
    const int MOD = 99999999977;
    
    vector<int> powers(NUM_POWERS);
    auto start = chrono::high_resolution_clock::now();

    // Generate powers
    int p = 1;
    for(int i = 0; i < NUM_POWERS; i++) {
        powers[i] = p;
        p = (p * BASE) % MOD;
    }

    // Write to text file (one power per line)
    ofstream out_file("powers_of_128.txt");
    if (!out_file) {
        cerr << "Error opening file!\n";
        return 1;
    }
    
    for(const auto& power : powers) {
        out_file << power << "\n";
    }
    out_file.close();

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = end - start;

    cout << "Generated " << powers.size() << " powers of " << BASE << "\n";
    cout << "Time taken: " << elapsed.count() << " seconds\n";
    cout << "File size: " 
         << powers.size() * sizeof(uint64_t) / (1024.0 * 1024.0) 
         << " MB (estimated binary size)\n";

    return 0;
}