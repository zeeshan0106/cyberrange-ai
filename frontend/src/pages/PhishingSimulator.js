import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Mail, AlertTriangle, Eye, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card } from "@/components/ui/card";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export const PhishingSimulator = () => {
  const [config, setConfig] = useState({
    target_role: "Employee",
    difficulty: "Medium",
    industry: "IT"
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showAnalysis, setShowAnalysis] = useState(false);
  
  const handleGenerate = async () => {
    setLoading(true);
    setShowAnalysis(false);
    try {
      const response = await axios.post(`${API}/phishing/generate`, config);
      setResult(response.data);
      toast.success("Phishing email generated successfully");
    } catch (error) {
      console.error(error);
      toast.error("Failed to generate phishing email");
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="py-8" data-testid="phishing-simulator-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-3 mb-8">
          <Mail className="w-8 h-8 text-primary" />
          <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-primary">
            Phishing Simulator
          </h1>
        </div>
        
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Configuration Panel */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
            <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground">
              Email Configuration
            </h2>
            
            <div className="space-y-6">
              <div>
                <Label htmlFor="role" className="text-sm font-mono text-muted-foreground mb-2 block">
                  Target Role
                </Label>
                <Select
                  value={config.target_role}
                  onValueChange={(value) => setConfig({...config, target_role: value})}
                >
                  <SelectTrigger id="role" data-testid="select-role" className="bg-black/50 border-white/20 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-black border-white/20">
                    <SelectItem value="Employee">Employee</SelectItem>
                    <SelectItem value="HR">HR</SelectItem>
                    <SelectItem value="Finance">Finance</SelectItem>
                    <SelectItem value="Student">Student</SelectItem>
                    <SelectItem value="Admin">Admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div>
                <Label htmlFor="difficulty" className="text-sm font-mono text-muted-foreground mb-2 block">
                  Difficulty Level
                </Label>
                <Select
                  value={config.difficulty}
                  onValueChange={(value) => setConfig({...config, difficulty: value})}
                >
                  <SelectTrigger id="difficulty" data-testid="select-difficulty" className="bg-black/50 border-white/20 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-black border-white/20">
                    <SelectItem value="Easy">Easy</SelectItem>
                    <SelectItem value="Medium">Medium</SelectItem>
                    <SelectItem value="Advanced">Advanced</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div>
                <Label htmlFor="industry" className="text-sm font-mono text-muted-foreground mb-2 block">
                  Industry
                </Label>
                <Select
                  value={config.industry}
                  onValueChange={(value) => setConfig({...config, industry: value})}
                >
                  <SelectTrigger id="industry" data-testid="select-industry" className="bg-black/50 border-white/20 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-black border-white/20">
                    <SelectItem value="IT">IT</SelectItem>
                    <SelectItem value="Banking">Banking</SelectItem>
                    <SelectItem value="Education">Education</SelectItem>
                    <SelectItem value="Healthcare">Healthcare</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <Button
                onClick={handleGenerate}
                disabled={loading}
                data-testid="generate-phishing-btn"
                className="w-full bg-primary text-primary-foreground hover:bg-primary/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest cyber-glow"
              >
                {loading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  "Generate Phishing Email"
                )}
              </Button>
            </div>
          </div>
          
          {/* Email Preview */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
            <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground">
              Email Preview
            </h2>
            
            {result ? (
              <div className="space-y-4" data-testid="email-preview">
                <div className="bg-black/60 border border-white/20 rounded-sm p-4">
                  <div className="text-xs font-mono text-muted-foreground mb-2">SUBJECT:</div>
                  <div className="font-mono text-sm text-foreground">{result.subject}</div>
                </div>
                
                <div className="bg-black/60 border border-white/20 rounded-sm p-4 max-h-64 overflow-y-auto">
                  <div className="text-xs font-mono text-muted-foreground mb-2">BODY:</div>
                  <div className="font-mono text-sm text-foreground whitespace-pre-wrap">{result.body}</div>
                </div>
                
                <div className="bg-destructive/10 border border-destructive/30 rounded-sm p-4">
                  <div className="flex items-center gap-2 text-destructive mb-3">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-xs font-mono font-bold uppercase">Red Flags Detected</span>
                  </div>
                  <ul className="space-y-1">
                    {result.red_flags.map((flag, index) => (
                      <li key={index} className="text-sm font-mono text-destructive-foreground">
                        • {flag}
                      </li>
                    ))}
                  </ul>
                </div>
                
                <Button
                  onClick={() => setShowAnalysis(!showAnalysis)}
                  data-testid="reveal-analysis-btn"
                  variant="outline"
                  className="w-full border-accent text-accent hover:bg-accent/10 rounded-sm font-rajdhani uppercase tracking-widest"
                >
                  <Eye className="mr-2 h-4 w-4" />
                  {showAnalysis ? "Hide Analysis" : "Reveal Analysis"}
                </Button>
                
                {showAnalysis && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    className="bg-accent/10 border border-accent/30 rounded-sm p-4"
                    data-testid="analysis-section"
                  >
                    <div className="text-xs font-mono text-accent mb-2 font-bold uppercase">Analysis:</div>
                    <div className="text-sm font-mono text-foreground whitespace-pre-wrap">{result.analysis}</div>
                  </motion.div>
                )}
              </div>
            ) : (
              <div className="flex items-center justify-center h-64 text-muted-foreground">
                <div className="text-center">
                  <Mail className="w-16 h-16 mx-auto mb-4 opacity-30" />
                  <p className="font-mono text-sm">Configure and generate a phishing email</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default PhishingSimulator;
