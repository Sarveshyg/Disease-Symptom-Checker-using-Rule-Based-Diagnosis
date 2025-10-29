#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <string>
#include <sstream>
#include <fstream>
#include <iomanip> 

using namespace std;

class SymptomChecker {
private:
    map<string, set<string>> diseaseRules;

    string trim(const string &str) {
        size_t start = str.find_first_not_of(" \t");
        size_t end = str.find_last_not_of(" \t");
        if (start == string::npos)
            return "";
        return str.substr(start, end - start + 1);
    }

public:
    void loadRules(const string &filename) {
        fstream rule(filename, ios::in);
        if (!rule.is_open()) {
            cerr << "Error: Failed to open rule file: " << filename << endl;
            return;
        }

        string data;
        while (getline(rule, data)) {
            if (data.empty()) continue;

            size_t colonPos = data.find(':');
            if (colonPos == string::npos) continue;

            string diseaseName = trim(data.substr(0, colonPos));
            string diseaseSymptoms = trim(data.substr(colonPos + 1));

            stringstream ss(diseaseSymptoms);
            string individualSymptom;
            while (getline(ss, individualSymptom, ',')) {
                diseaseRules[diseaseName].insert(trim(individualSymptom));
            }
        }
    }

    map<string, double> diagnose(const set<string> &userSymptoms) {
        map<string, double> diseaseScores;
        for (auto &[disease, symptoms] : diseaseRules) {
            
            if (symptoms.empty()) continue;

            int count = 0;
            for (auto &s : symptoms) {
                if (userSymptoms.find(s) != userSymptoms.end()) {
                    count++;
                }
            }
            double percentage = static_cast<double>(count) / symptoms.size();
            diseaseScores[disease] = percentage;
        }
        return diseaseScores;
    }
};

int main(int argc, char *argv[]) {
    if (argc < 2) {
        cout << "Usage: " << argv[0] << " symptom1 symptom2 symptom3" << endl;
        return 1;
    }

    SymptomChecker checker;
    checker.loadRules("rules.txt");

    set<string> userSymptoms;
    for (int i = 1; i < argc; ++i) {
        userSymptoms.insert(string(argv[i]));
    }

    map<string, double> diseaseScores = checker.diagnose(userSymptoms);
    
    cout << fixed << setprecision(2);

    for (auto &[disease, score] : diseaseScores) {
        if (score > 0) {
            cout << disease << ":" << score << endl;
        }
    }

    return 0;
}