# CyberRange AI - Setup & Run Guide for Another Laptop

This guide explains how to set up and run this project from scratch on any Windows laptop.

---

## 1. Prerequisites (Install Before Running)

Make sure the following 3 tools are installed on the laptop:

1. **Python (3.10 or higher)**:
   - Download from: [python.org](https://www.python.org/downloads/)
   - ⚠️ **CRITICAL STEP**: During installation, **CHECK the box: "Add python.exe to PATH"**.

2. **Node.js (LTS version)**:
   - Download from: [nodejs.org](https://nodejs.org/) (Download the Recommended/LTS installer).

3. **MongoDB Community Server**:
   - Download from: [mongodb.com/try/download/community](https://www.mongodb.com/try/download/community)
   - Install with default settings as a "Complete" installation.

---

## 2. Transferring the Project Files

When copying/zipping the project folder:
- **DO NOT copy the `frontend/node_modules` folder** (it is very large; you will reinstall it cleanly in Step 3).
- **Ensure both `.env` files are included**:
  - `backend/.env`
  - `frontend/.env`

---

## 3. One-Time Setup (First Time Only)

Open **PowerShell** as Administrator or standard user in the project folder:

### A. Install Backend Python Libraries
```powershell
cd backend
pip install -r requirements.txt
cd ..
```

### B. Install Frontend React Dependencies
```powershell
cd frontend
npm install
cd ..
```
> ⚠️ **CRITICAL WARNING**: Do **NOT** run `npm audit fix --force`!  
> `npm audit fix --force` installs incompatible breaking versions that destroy project dependencies. Standard `npm install` is all that is needed.


---

## 4. How to Start the Project

### Option A: One-Command Start (Recommended)

In PowerShell at the project root:
```powershell
# Allow script execution if Windows blocks it
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Start all services
.\start_servers.ps1
```

Once you see `Compiled successfully!`, open your browser at:
👉 **http://localhost:3000**

---

### Option B: Manual Start (3 Terminal Windows)

If you prefer starting each service manually in its own terminal:

#### Terminal 1: MongoDB
```powershell
& "C:\Program Files\MongoDB\Server\8.2\bin\mongod.exe" --dbpath "data\db" --port 27017 --bind_ip 127.0.0.1
```
*(If your MongoDB version is different, adjust `8.2` to your installed version number e.g. `7.0` or `8.0`)*

#### Terminal 2: Backend (FastAPI)
```powershell
cd backend
python -m uvicorn server:app --reload --port 8000
```

#### Terminal 3: Frontend (React)
```powershell
cd frontend
npm start
```

---

## 5. How to Stop the Project

- If using the **manual method**: Press `Ctrl + C` in each terminal window.
- If using **Option A (`start_servers.ps1`)**: Run:
  ```powershell
  .\stop_servers.ps1
  ```

---

## 6. URLs to Present During Viva

- **Web Application UI**: `http://localhost:3000`
- **Backend API Base**: `http://localhost:8000/api/`
- **Interactive Swagger API Documentation**: `http://localhost:8000/docs`
