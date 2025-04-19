#include <bits/stdc++.h>
using namespace std;
#define int unsigned long long

const int NUM_POWERS = 1e6;
const int BASE = 128;
const int MOD = 99999999977;;

int generateHash(string &s, vector<int>& powers) {
    int h = 0;
    int n = s.size();
    for(int i = 0; i < n; i++) {
        h = ((h + (s[i] * powers[i]) % MOD)) % MOD;
    }
    return h;
}

int stringToInt(string &s){
    int n = s.size();

    int x = 0;
    for(char c : s){
        x = 10 * x + (c - '0');
    }

    return x;
}

vector<int> read_numbers(string &filename) {
    vector<int> lines;
    ifstream file(filename);
    
    string line;
    while (getline(file, line)) {
        lines.push_back(stringToInt(line));
    }

    return lines;
}

vector<string> read_file_to_vector(const string& filename) {
    vector<string> lines;
    ifstream file(filename);
    
    string line;
    while (getline(file, line)) {
        lines.push_back(line);
    }

    return lines;
}

int32_t main() {
    string powerPath = "./powers_of_128.txt";
   vector<int>powers = read_numbers(powerPath);
    vector<string> lines = read_file_to_vector("./malicous_queries.txt");

    int n = lines.size();
    vector<int> maliciousHash(n);
   
    // Generate all hashes
    for(int i = 0; i < n; i++) {
        maliciousHash[i] = generateHash(lines[i], powers);
    }
    sort(maliciousHash.begin(),maliciousHash.end());
    // Write hashes to text file (one per line)
    ofstream out_file("malicious_hashes.txt");
    if (!out_file) {
        cerr << "Error opening output file!\n";
        return 1;
    }
    
    for(const auto& hash : maliciousHash) {
        out_file << hash << "\n";
    }
    out_file.close();

    cout << "Successfully wrote " << n << " hashes to malicious_hashes.bin\n";
    return 0;
}