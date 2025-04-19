#include<bits/stdc++.h>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <climits>
#include <algorithm>
using namespace std;
#define int  unsigned long long

const int NUM_POWERS = 1e6;
const int BASE = 128;
const int MOD = 99999999977;;

int generateHash(string &s , vector<int>&powers){
    int h = 0;

    int n = s.size();
   
    for(int i=0;i<n;i++){
        
        h = ((h + (s[i] * powers[i])%MOD))%MOD;
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

int32_t main(int32_t argc , char * argv[]){
    string powerPath = "C:/Users/lokesh/Desktop/hack/Protection/middleware/algorithims/powers_of_128.txt";
    string hashPath = "C:/Users/lokesh/Desktop/hack/Protection/middleware/algorithims/malicious_hashes.txt";
    vector<int>powers = read_numbers(powerPath);
    vector<int>malicous_hash = read_numbers(hashPath);
    
    try{
        for(int i=1;i<argc;i++){
            string s = argv[i];
     
            int h = generateHash(s , powers);
           
            int idx = lower_bound(malicous_hash.begin(),malicous_hash.end(),h) - malicous_hash.begin();
            // cout<<s<<"\n";
            // cout<<h<<" "<<malicous_hash[idx]<<"\n";
            if(idx == -1 || malicous_hash[idx] != h){
                cout<<s<<endl;
            }
            else{
                cout<<"malicious"<<endl;
            }
        }
    }  
     catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    }
    
   
    return 0;


}