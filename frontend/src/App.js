import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import Layout from "@/components/Layout";
import Home from "@/pages/Home";
import PhishingSimulator from "@/pages/PhishingSimulator";
import RansomwareSimulator from "@/pages/RansomwareSimulator";
import AttackScenario from "@/pages/AttackScenario";
import TrainingMode from "@/pages/TrainingMode";
import Dashboard from "@/pages/Dashboard";
import About from "@/pages/About";
import { MultiplayerMode } from "@/pages/MultiplayerMode";

function App() {
  return (
    <div className="App">
      <div className="scanlines" />
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/phishing" element={<PhishingSimulator />} />
            <Route path="/ransomware" element={<RansomwareSimulator />} />
            <Route path="/attack-scenario" element={<AttackScenario />} />
            <Route path="/training" element={<TrainingMode />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/multiplayer" element={<MultiplayerMode />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </Layout>
      </BrowserRouter>
      <Toaster />
    </div>
  );
}

export default App;
