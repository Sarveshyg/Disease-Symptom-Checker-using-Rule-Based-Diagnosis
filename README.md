# 🩺 Rule-Based Disease Symptom Checker (Full-Stack C++/Flask)

This project is a web-based symptom checker that utilizes a rule-based expert system written in **C++** for its core diagnosis logic. A **Python Flask API** serves as the backend bridge, communicating the user's symptoms from the **Tailwind CSS/JavaScript frontend** to the compiled C++ program and returning the diagnostic scores.

## ✨ Key Features

  * **Rule-Based Diagnosis (C++):** The core logic calculates disease match scores based on a predefined rule set. It operates entirely as a standalone, compiled C++ executable, fulfilling the core project requirement.
  * **Closest Match Scoring:** The system calculates a match percentage (`0.0` to `1.0`) for every disease based on the ratio of matching symptoms to required symptoms, enabling partial and closest-possible diagnoses.
  * **Modern Frontend (UI/UX):** A sleek, responsive interface built with HTML/JavaScript and styled using **Tailwind CSS**. Features an animated gradient background and an intuitive display showing the top diagnosis first.
  * **Asynchronous Communication:** The Flask API acts as the bridge, executing the C++ program via the `subprocess` module and handling all data communication between the frontend and the C++ backend.
  * **Easy Rule Modification:** All diagnostic rules are stored externally in `rules.txt`, allowing for easy modification without recompiling the C++ core.

-----

## ⚙️ Architecture

The application follows a three-layer architecture:

1.  **Frontend (`templates/index.html`):** Collects user input and makes a `POST` request (via JavaScript `fetch`) to the Flask API.
2.  **API Bridge (`app.py`):** Receives the JSON data, executes the C++ program (`code.exe` or `./code`) via `subprocess`, parses the `stdout` string, and returns the scores as JSON.
3.  **Core Logic (`code.cpp`):** Reads rules from `rules.txt`, processes symptoms received via **command-line arguments** (`argv`), calculates scores, and prints the result to standard output (`stdout`).

-----

## 🚀 Setup and Running the Application

To run this application, you must first compile the C++ program and then run the Python server.

### Prerequisites

1.  **C++ Compiler (GCC/g++):** Required to compile `code.cpp`.
2.  **Python 3.x and pip:** Required for the Flask server.

### Step 1: Clone and Organize the Project

Ensure your project structure matches the server's expectations. Your logo and compiled executable must be in the correct locations.

```
/Your-Project-Folder/
├── app.py               # Flask Server
├── code.cpp             # Core Logic
├── rules.txt            # Rule Base
├── code.exe             # 🛠️ COMPILED C++ EXECUTABLE
├── templates/
│   └── index.html       # Frontend HTML
└── static/              # Flask looks here for images/CSS/JS
    └── logo.png         # Static Assets (Logo)
```

### Step 2: Compile the C++ Core

Compile `code.cpp` to an executable named `code.exe` (or just `code` on Linux/Mac).

Open your terminal in the project folder and run the following compilation command:

```bash
g++ code.cpp -o code.exe
```

### Step 3: Install Python Dependencies

Install the necessary libraries for the Flask server:

```bash
pip install Flask flask-cors
```

### Step 4: Run the Flask Server

Start the application by running the Python server:

```bash
python app.py
```

The server will start, typically running on `http://127.0.0.1:5000`.

-----

## 💻 Usage

1.  Open your web browser and navigate to the server address (e.g., **`http://127.0.0.1:5000`**).
2.  Enter your symptoms separated by commas (e.g., `fever, severe_cough, headache`).
3.  Click **Diagnose**.
4.  The top result (highest score) will be displayed. Click the **Show other possibilities** arrow to reveal all other partial matches and their percentage scores.

-----

## 🎯 C++ Input/Output Protocol

The communication between Python and C++ relies on a strict I/O protocol:

### C++ Input (Arguments)

The C++ program receives all symptoms as command-line arguments.

  * **Example Call:** `.\code.exe fever cough headache`
  * **C++:** Reads arguments using `int main(int argc, char* argv[])`.

### C++ Output (`stdout`)

The C++ program must print the output in a simple, machine-readable key-value format.

  * **Required Format:** `DiseaseName:Score` (one per line, with no extra characters or text).
  * **Example Output (printed to the console):**
    ```
    Flu:1.00
    CommonCold:0.66
    Migraine:0.25
    ```
  * **Python:** The Flask server captures this exact `stdout` string and parses it.
