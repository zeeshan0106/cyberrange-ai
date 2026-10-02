import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Zap, Loader2, ShieldAlert, Crosshair } from "lucide-react";
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
  
  const getDetectionBadge = (likelihood) => {
    switch (likelihood?.toLowerCase()) {
      case 'low':
        return 'border-destructive/40 bg-destructive/10 text-destructive';
      case 'medium':
        return 'border-secondary/40 bg-secondary/10 text-secondary';
      case 'high':
        return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400';
      default:
        return 'border-white/20 bg-black/40 text-muted-foreground';
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
            <h2 className="text-2xl font-rajdhani font-bold uppercase mb-4 text-primary">
              {result.title}
            </h2>

            {/* Scenario Summary */}
            {result.summary && (
              <div className="mb-8 p-4 bg-primary/5 border border-primary/20 rounded-sm">
                <div className="flex items-center gap-2 mb-2 text-primary font-rajdhani font-bold uppercase tracking-wider text-sm">
                  <ShieldAlert className="w-4 h-4 text-primary" />
                  Executive Threat Summary
                </div>
                <p className="text-sm font-mono text-muted-foreground leading-relaxed">
                  {result.summary}
                </p>
              </div>
            )}
            
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
                    
                    <div className="bg-black/60 border border-white/20 rounded-sm p-6 space-y-4">
                      {/* Header Row: Stage Name & Time + Badges */}
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <h3 className="text-lg font-rajdhani font-bold uppercase text-primary">
                            {event.stage}
                          </h3>
                          <p className="text-xs font-mono text-muted-foreground mt-1">
                            {event.time}
                          </p>
                        </div>

                        <div className="flex flex-wrap items-center gap-2">
                          {/* MITRE Tactic Label */}
                          {event.tactic && (
                            <span className="text-xs font-mono font-bold uppercase px-2.5 py-1 rounded-sm bg-accent/10 border border-accent/30 text-accent">
                              {event.tactic}
                            </span>
                          )}

                          {/* Color-coded Detection Likelihood Badge */}
                          {event.detection_likelihood && (
                            <span className={`text-xs font-mono font-bold uppercase px-2.5 py-1 rounded-sm border ${getDetectionBadge(event.detection_likelihood)}`}>
                              Detection: {event.detection_likelihood}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* MITRE Technique Badges */}
                      {event.techniques && event.techniques.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                          {event.techniques.map((tech, tIdx) => (
                            <span
                              key={tIdx}
                              className="text-xs font-mono px-2.5 py-1 rounded-sm bg-white/5 border border-white/10 text-zinc-200 flex items-center gap-1.5"
                            >
                              <Crosshair className="w-3 h-3 text-accent shrink-0" />
                              <span className="font-bold text-accent">{tech.technique_id}</span>
                              <span className="text-white/30">|</span>
                              <span className="text-zinc-200 font-medium">{tech.technique_name}</span>
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Description */}
                      <p className="text-sm font-mono text-foreground leading-relaxed">
                        {event.description}
                      </p>

                      {/* Unified Section for Impact, Detection Hint & Mitigation */}
                      {(event.impact || event.detection_hint || event.mitigation) && (
                        <div className="pt-3 border-t border-white/10 space-y-2.5 text-xs font-mono">
                          {event.impact && (
                            <div className="flex items-start gap-2 bg-white/[0.02] p-2.5 rounded-sm border border-white/5">
                              <span className="font-bold text-destructive uppercase tracking-wider shrink-0">Impact:</span>{" "}
                              <span className="text-foreground/90 leading-relaxed">{event.impact}</span>
                            </div>
                          )}
                          {event.detection_hint && (
                            <div className="flex items-start gap-2 bg-white/[0.02] p-2.5 rounded-sm border border-white/5">
                              <span className="font-bold text-secondary uppercase tracking-wider shrink-0">Detection Hint:</span>{" "}
                              <span className="text-muted-foreground leading-relaxed">{event.detection_hint}</span>
                            </div>
                          )}
                          {event.mitigation && (
                            <div className="flex items-start gap-2 bg-white/[0.02] p-2.5 rounded-sm border border-white/5">
                              <span className="font-bold text-accent uppercase tracking-wider shrink-0">Mitigation:</span>{" "}
                              <span className="text-muted-foreground leading-relaxed">{event.mitigation}</span>
                            </div>
                          )}
                        </div>
                      )}
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
