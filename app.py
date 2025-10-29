import subprocess  
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS  


app = Flask(__name__)

CORS(app) 



@app.route('/')
def home():
    
    return render_template('index.html') 




@app.route('/diagnose', methods=['POST'])
def diagnose_symptoms():
    try:
        
        data = request.get_json()
        symptoms = data.get('symptoms', []) 

        
        
        
        command = ['./code.exe'] + symptoms 

        
        
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        
        
        
        output_lines = result.stdout.strip().split('\n')
        
        disease_scores = {}
        for line in output_lines:
            if ':' in line:
                disease, score = line.split(':')
                disease_scores[disease] = float(score) 

        
        return jsonify(disease_scores)

    except subprocess.CalledProcessError as e:
        
        print(f"C++ Error: {e.stderr}")
        return jsonify({"error": "Diagnosis failed", "details": e.stderr}), 500
    except Exception as e:
        
        print(f"Server Error: {e}")
        return jsonify({"error": "An internal server error occurred"}), 500


if __name__ == '__main__':
    
    app.run(debug=True, port=5000)