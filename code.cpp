#include <iostream>
#include <map>
#include <vector>
#include <bits/stdc++.h>
#include <sstream>
using namespace std;

string trim(const string &str)
{
    size_t start = str.find_first_not_of(" \t");
    size_t end = str.find_last_not_of(" \t");
    if (start == string::npos)
        return "";
    return str.substr(start, end - start + 1);
}

void gather_disease(map<string, set<string>> &diseaseRules)
{
    fstream rule("rules.txt", ios::in);
    string data;
    if (!rule.is_open())
    {
        cerr << "Failed to open the file. Please check if it exists.";
        return;
    }
    while (getline(rule, data))
    {
        if (data.empty())
            continue;

        size_t colonPos = data.find(':');
        if (colonPos == string::npos)
            continue;

        string diseaseName = trim(data.substr(0, colonPos));
        string diseaseSymptoms = trim(data.substr(colonPos + 1));

        stringstream ss(diseaseSymptoms);
        string individualSymptom;
        while (getline(ss, individualSymptom, ','))
        {
            individualSymptom = trim(individualSymptom);
            diseaseRules[diseaseName].insert(individualSymptom);
        }
    }
}

set<string> get_user_symptoms()
{
    set<string> userDisease;
    string userInput;

    do
    {
        cout << "Enter your symptoms one at a time: ";
        getline(cin, userInput);
        if (userInput == "done" || userInput.empty())
        {
            break;
        }
        userInput = trim(userInput);
        userDisease.insert(userInput);
    } while (true);

    return userDisease;
}

set<string> diagnose(map<string, set<string>> &diseaseRules, set<string> &userSymptoms)
{
    set<string> possibleDiseases;

    for (auto &[disease, symptoms] : diseaseRules)
    {
        bool allSymptomsMatch = true;
        for (auto &s : symptoms)
        {
            if(userSymptoms.find(s) == userSymptoms.end()){
                allSymptomsMatch = false;
                break;
            }
        }

        if(allSymptomsMatch)
            possibleDiseases.insert(disease);
    }

    return possibleDiseases;
}

int main()
{
    map<string, set<string>> diseaseRules;
    gather_disease(diseaseRules);

    set<string> userSymptoms = get_user_symptoms();

    set<string> userDisease = diagnose(diseaseRules, userSymptoms);
    cout << "Potential Disease: ";
    for(auto& ud: userDisease){
        cout << ud << " ";
    }

    return 0;
}