# CyberRange AI

CyberRange AI is an interactive cybersecurity training and simulation platform designed to help users understand and practice responding to various cyber threats. The platform leverages AI (mocked/simulated) to generate dynamic attack scenarios, phishing emails, and training questions.

## Features

- **Dashboard**: Overview of simulation statistics and training progress.
- **Phishing Simulator**: Generate realistic phishing emails with red flag analysis.
- **Ransomware Simulator**: Simulate ransomware attack vectors, infection flows, and mitigation strategies.
- **Attack Scenarios**: Create complex, multi-stage cyber attack scenarios (APTs) based on organization type and security maturity.
- **Training Mode**: Interactive quizzes with dynamic, randomized questions across multiple cybersecurity domains (Phishing, Ransomware, Incident Response, General Security).

## Tech Stack

### Backend
- **Framework**: FastAPI (Python)
- **Database**: MongoDB (using Motor for async driver)
- **Server**: Uvicorn

### Frontend
- **Framework**: React.js
- **Styling**: Tailwind CSS
- **UI Components**: Radix UI, Lucide React
- **Routing**: React Router
- **HTTP Client**: Axios

## Project Structure

```
cyberrange-ai/
├── backend/            # FastAPI server and API logic
│   ├── server.py       # Main application entry point
│   ├── .env            # Environment variables (not committed)
│   └── requirements.txt # Python dependencies
├── frontend/           # React frontend application
│   ├── src/            # Source code
│   │   ├── components/ # Reusable UI components
│   │   ├── pages/      # Application pages/views
│   │   └── ...
│   └── package.json    # Node.js dependencies
└── README.md           # Project documentation
```

## Getting Started

### Prerequisites

- Python 3.8+
- Node.js 14+ and npm/yarn
- MongoDB instance (local or cloud)

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the `backend` directory with the following variables:
   ```env
   MONGO_URL=mongodb://localhost:27017
   DB_NAME=cyberrange_db
   CORS_ORIGINS=http://localhost:3000
   ```

5. Start the backend server:
   ```bash
   python3 -m uvicorn backend.server:app --reload --port 8000
   ```
   The API will be available at `http://localhost:8000`.

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```

3. Start the development server:
   ```bash
   npm start
   # or
   yarn start
   ```
   The application will open at `http://localhost:3000`.

## Usage

1. Open your browser and navigate to `http://localhost:3000`.
2. Explore the **Dashboard** to see your stats.
3. Use the **Phishing** and **Ransomware** simulators to generate and analyze threats.
4. Go to **Training Mode** to test your knowledge with randomized questions.
5. Generate custom **Attack Scenarios** to understand complex threat lifecycles.

## License

[MIT](https://choosealicense.com/licenses/mit/)
