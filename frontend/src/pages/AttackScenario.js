import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Zap, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export const AttackScenario = () => {
  const [config, setConfig] = useState({
    organization_type: "Tech Startup",
    security_maturity: "Medium"
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  
  const handleGenerate = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/attack-scenario/generate`, config);
      setResult(response.data);
      toast.success("Attack scenario generated");
    } catch (error) {
      console.error(error);
      toast.error("Failed to generate scenario");
    } finally {
      setLoading(false);
    }
  };
  
  const getImpactColor = (impact) => {
    switch (impact?.toLowerCase()) {
      case 'low': return 'text-accent';
      case 'medium': return 'text-secondary';
      case 'high': return 'text-destructive';
      case 'critical': return 'text-destructive animate-pulse';
      default: return 'text-muted-foreground';
    }
  };
  
  return (
    <div className="py-8" data-testid="attack-scenario-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-3 mb-8">
          <Zap className="w-8 h-8 text-accent" />
          <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-accent">
            Attack Scenario Generator
          </h1>
        </div>
        
        {/* Configuration */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 mb-6">
          <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground">
            Scenario Configuration
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div>
              <Label htmlFor="org-type" className="text-sm font-mono text-muted-foreground mb-2 block">
                Organization Type
              </Label>
              <Select
                value={config.organization_type}
                onValueChange={(value) => setConfig({...config, organization_type: value})}
              >
                <SelectTrigger id="org-type" data-testid="select-org-type" className="bg-black/50 border-white/20 font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-black border-white/20">
                  <SelectItem value="Tech Startup">Tech Startup</SelectItem>
                  <SelectItem value="Enterprise">Large Enterprise</SelectItem>
                  <SelectItem value="Government">Government Agency</SelectItem>
                  <SelectItem value="SMB">Small-Medium Business</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div>
              <Label htmlFor="maturity" className="text-sm font-mono text-muted-foreground mb-2 block">
                Security Maturity
              </Label>
              <Select
                value={config.security_maturity}
                onValueChange={(value) => setConfig({...config, security_maturity: value})}
              >
                <SelectTrigger id="maturity" data-testid="select-security-maturity" className="bg-black/50 border-white/20 font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-black border-white/20">
                  <SelectItem value="Low">Low</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          
          <Button
            onClick={handleGenerate}
            disabled={loading}
            data-testid="generate-scenario-btn"
            className="bg-accent text-accent-foreground hover:bg-accent/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              "Generate Attack Scenario"
            )}
          </Button>
        </div>
        
        {/* Results */}
        {result && (
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6" data-testid="scenario-result">
            <h2 className="text-2xl font-rajdhani font-bold uppercase mb-8 text-primary">
              {result.title}
            </h2>
            
            {/* Timeline */}
            <div className="relative">
              {/* Vertical line */}
              <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-primary/30" />
              
              <div className="space-y-6">
                {result.timeline.map((event, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="relative pl-12"
                  >
                    {/* Timeline dot */}
                    <div className="absolute left-0 w-8 h-8 rounded-full bg-primary border-4 border-background flex items-center justify-center">
                      <div className="w-2 h-2 rounded-full bg-background" />
                    </div>
                    
                    <div className="bg-black/60 border border-white/20 rounded-sm p-6">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className="text-lg font-rajdhani font-bold uppercase text-primary">
                            {event.stage}
                          </h3>
                          <p className="text-xs font-mono text-muted-foreground mt-1">
                            {event.time}
                          </p>
                        </div>
                        <span className={`text-xs font-mono font-bold uppercase px-3 py-1 rounded-sm border ${getImpactColor(event.impact)} border-current`}>
                          {event.impact} Impact
                        </span>
                      </div>
                      <p className="text-sm font-mono text-foreground">
                        {event.description}
                      </p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default AttackScenario;
