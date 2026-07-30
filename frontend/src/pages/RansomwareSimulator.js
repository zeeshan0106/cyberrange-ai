import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Bug, Shield, AlertTriangle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export const RansomwareSimulator = () => {
  const [config, setConfig] = useState({
    attack_vector: "Email",
    organization_type: "IT Company"
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const handleGenerate = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/ransomware/generate`, config);
      setResult(response.data);
      toast.success("Ransomware scenario generated");
    } catch (error) {
      console.error(error);
      toast.error("Failed to generate scenario");
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="py-8" data-testid="ransomware-simulator-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-3 mb-8">
          <Bug className="w-8 h-8 text-destructive" />
          <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-destructive">
            Ransomware Simulator
          </h1>
        </div>
        
        {/* Configuration */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 mb-6">
          <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground">
            Attack Configuration
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div>
              <Label htmlFor="vector" className="text-sm font-mono text-muted-foreground mb-2 block">
                Attack Vector
              </Label>
              <Select
                value={config.attack_vector}
                onValueChange={(value) => setConfig({...config, attack_vector: value})}
              >
                <SelectTrigger id="vector" data-testid="select-attack-vector" className="bg-black/50 border-white/20 font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-black border-white/20">
                  <SelectItem value="Email">Email Attachment</SelectItem>
                  <SelectItem value="USB">USB Drive</SelectItem>
                  <SelectItem value="RDP">RDP Exploit</SelectItem>
                  <SelectItem value="Malicious Link">Malicious Link</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <Label htmlFor="org" className="text-sm font-mono text-muted-foreground mb-2 block">
                Organization Type
              </Label>
              <Select
                value={config.organization_type}
                onValueChange={(value) => setConfig({...config, organization_type: value})}
              >
                <SelectTrigger id="org" data-testid="select-org-type" className="bg-black/50 border-white/20 font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-black border-white/20">
                  <SelectItem value="IT Company">IT Company</SelectItem>
                  <SelectItem value="Healthcare">Healthcare</SelectItem>
                  <SelectItem value="Financial">Financial Institution</SelectItem>
                  <SelectItem value="Education">Educational Institution</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <Button
            onClick={handleGenerate}
            disabled={loading}
            data-testid="generate-ransomware-btn"
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              "Generate Ransomware Scenario"
            )}
          </Button>
        </div>
        
        {/* Results */}
        {result && (
          <div className="space-y-6" data-testid="ransomware-result">
            {/* Infection Flow */}
            <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
              <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                Infection Flow
              </h2>
              
              <div className="space-y-3">
                {result.infection_flow.map((step, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-start gap-4"
                  >
                    <div className="flex-shrink-0 w-8 h-8 rounded-sm bg-destructive/20 border border-destructive flex items-center justify-center text-destructive font-mono text-sm font-bold">
                      {index + 1}
                    </div>
                    <div className="flex-1 bg-black/60 border border-white/20 rounded-sm p-4">
                      <p className="font-mono text-sm text-foreground">{step}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
            
            {/* MITRE ATT&CK Mapping */}
            <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
              <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground">
                MITRE ATT&CK Mapping
              </h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {result.mitre_mapping.map((technique, index) => (
                  <div key={index} className="bg-secondary/10 border border-secondary/30 rounded-sm p-4">
                    <div className="text-xs font-mono text-secondary font-bold mb-1">
                      {technique.id}
                    </div>
                    <div className="text-sm font-mono text-foreground">
                      {technique.name}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            
            {/* Prevention Tips */}
            <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
              <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground flex items-center gap-2">
                <Shield className="w-5 h-5 text-accent" />
                Prevention Tips
              </h2>
              
              <ul className="space-y-3">
                {result.prevention_tips.map((tip, index) => (
                  <li key={index} className="flex items-start gap-3">
                    <div className="flex-shrink-0 w-2 h-2 rounded-full bg-accent mt-2" />
                    <p className="font-mono text-sm text-foreground">{tip}</p>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default RansomwareSimulator;
