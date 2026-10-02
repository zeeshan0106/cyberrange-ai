import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Bug, Shield, AlertTriangle, Loader2, Crosshair, Zap, BookOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

// Helper: tactic color badge
const getTacticBadgeClass = (tactic) => {
  const t = (tactic || "").toLowerCase();
  if (t.includes("initial")) return "bg-destructive/15 border-destructive/40 text-destructive";
  if (t.includes("execution")) return "bg-orange-500/15 border-orange-500/40 text-orange-400";
  if (t.includes("persistence")) return "bg-yellow-500/15 border-yellow-500/40 text-yellow-400";
  if (t.includes("privilege")) return "bg-amber-500/15 border-amber-500/40 text-amber-400";
  if (t.includes("defense")) return "bg-purple-500/15 border-purple-500/40 text-purple-400";
  if (t.includes("credential")) return "bg-pink-500/15 border-pink-500/40 text-pink-400";
  if (t.includes("discovery")) return "bg-sky-500/15 border-sky-500/40 text-sky-400";
  if (t.includes("lateral")) return "bg-indigo-500/15 border-indigo-500/40 text-indigo-400";
  if (t.includes("collection")) return "bg-teal-500/15 border-teal-500/40 text-teal-400";
  if (t.includes("command")) return "bg-cyan-500/15 border-cyan-500/40 text-cyan-400";
  if (t.includes("exfil")) return "bg-secondary/15 border-secondary/40 text-secondary";
  if (t.includes("impact")) return "bg-destructive/15 border-destructive/40 text-destructive";
  return "bg-white/5 border-white/20 text-muted-foreground";
};

// Render new-format step (has tactic, technique_id, detection_hint, containment_action)
const StepCard = ({ step, index }) => (
  <motion.div
    key={index}
    initial={{ opacity: 0, x: -20 }}
    animate={{ opacity: 1, x: 0 }}
    transition={{ delay: index * 0.07 }}
    className="relative pl-12"
    data-testid={`ransomware-step-${index}`}
  >
    {/* Step number dot */}
    <div className="absolute left-0 w-8 h-8 rounded-sm bg-destructive/20 border border-destructive flex items-center justify-center text-destructive font-mono text-sm font-bold">
      {step.step_number || index + 1}
    </div>

    <div className="bg-black/60 border border-white/20 rounded-sm p-5 space-y-3">
      {/* Header: Title + Badges */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <h3 className="text-base font-rajdhani font-bold uppercase text-destructive leading-tight">
          {step.title}
        </h3>
        <div className="flex flex-wrap gap-2">
          {step.tactic && (
            <span className={`text-xs font-mono font-bold uppercase px-2.5 py-1 rounded-sm border ${getTacticBadgeClass(step.tactic)}`}>
              {step.tactic}
            </span>
          )}
        </div>
      </div>

      {/* MITRE technique badge */}
      {step.technique_id && (
        <div className="flex flex-wrap gap-2">
          <span className="text-xs font-mono px-2.5 py-1 rounded-sm bg-white/5 border border-white/10 flex items-center gap-1.5">
            <Crosshair className="w-3 h-3 text-accent shrink-0" />
            <span className="font-bold text-accent">{step.technique_id}</span>
            <span className="text-white/30">|</span>
            <span className="text-zinc-200 font-medium">{step.technique_name}</span>
          </span>
        </div>
      )}

      {/* Description */}
      <p className="text-sm font-mono text-foreground leading-relaxed">
        {step.description}
      </p>

      {/* Detection Hint & Containment block */}
      {(step.detection_hint || step.containment_action) && (
        <div className="pt-3 border-t border-white/10 space-y-2 text-xs font-mono">
          {step.detection_hint && (
            <div className="flex items-start gap-2 bg-white/[0.02] p-2.5 rounded-sm border border-white/5">
              <span className="font-bold text-secondary uppercase tracking-wider shrink-0">Detection Hint:</span>{" "}
              <span className="text-muted-foreground leading-relaxed">{step.detection_hint}</span>
            </div>
          )}
          {step.containment_action && (
            <div className="flex items-start gap-2 bg-white/[0.02] p-2.5 rounded-sm border border-white/5">
              <span className="font-bold text-accent uppercase tracking-wider shrink-0">Containment:</span>{" "}
              <span className="text-muted-foreground leading-relaxed">{step.containment_action}</span>
            </div>
          )}
        </div>
      )}
    </div>
  </motion.div>
);

// Legacy plain-string step rendering (backwards compat for old MongoDB docs)
const LegacyStepCard = ({ step, index }) => (
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
);

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

  // Determine if we have new-format steps (array of objects) or legacy (array of strings)
  const hasNewSteps = result?.steps && result.steps.length > 0 && typeof result.steps[0] === "object";
  const hasLegacyFlow = result?.infection_flow && result.infection_flow.length > 0;

  // Prevention tips: can be strings (legacy) or objects {text, addresses_step}
  const normalizeTips = (tips) => {
    if (!tips || tips.length === 0) return [];
    return tips.map((tip) => {
      if (typeof tip === "string") return { text: tip, addresses_step: null };
      return tip;
    });
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

            {/* Executive Threat Summary */}
            {result.summary && (
              <div className="bg-black/40 backdrop-blur-md border border-destructive/20 rounded-sm p-6">
                <div className="flex items-center gap-2 mb-3 text-destructive font-rajdhani font-bold uppercase tracking-wider text-sm">
                  <AlertTriangle className="w-4 h-4" />
                  Executive Threat Summary
                </div>
                <p className="text-sm font-mono text-muted-foreground leading-relaxed" data-testid="ransomware-summary">
                  {result.summary}
                </p>
              </div>
            )}

            {/* Attack Timeline — new format */}
            {hasNewSteps && (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
                <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" />
                  Attack Timeline
                </h2>
                <div className="relative">
                  <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-destructive/20" />
                  <div className="space-y-5">
                    {result.steps.map((step, index) => (
                      <StepCard key={index} step={step} index={index} />
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Legacy Infection Flow (for old MongoDB documents that lack steps array) */}
            {!hasNewSteps && hasLegacyFlow && (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
                <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" />
                  Infection Flow
                </h2>
                <div className="space-y-3">
                  {result.infection_flow.map((step, index) => (
                    <LegacyStepCard key={index} step={step} index={index} />
                  ))}
                </div>
              </div>
            )}

            {/* MITRE ATT&CK Mapping */}
            {result.mitre_mapping && result.mitre_mapping.length > 0 && (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
                <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground">
                  MITRE ATT&CK Mapping
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {result.mitre_mapping.map((technique, index) => (
                    <div key={index} className="bg-secondary/10 border border-secondary/30 rounded-sm p-4 flex items-start gap-3">
                      <Crosshair className="w-4 h-4 text-accent shrink-0 mt-0.5" />
                      <div>
                        <div className="text-xs font-mono text-accent font-bold mb-0.5">
                          {technique.id}
                        </div>
                        <div className="text-sm font-mono text-foreground">
                          {technique.name}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Response Plan */}
            {result.response_plan && (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
                <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground flex items-center gap-2">
                  <Zap className="w-5 h-5 text-secondary" />
                  Incident Response Plan
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-5">

                  {/* Immediate Actions */}
                  <div className="bg-destructive/5 border border-destructive/20 rounded-sm p-4">
                    <h3 className="text-sm font-rajdhani font-bold uppercase mb-4 text-destructive tracking-wider">
                      Immediate Actions
                    </h3>
                    <ul className="space-y-2.5">
                      {(result.response_plan.immediate_actions || []).map((action, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <div className="flex-shrink-0 w-5 h-5 rounded-sm bg-destructive/20 border border-destructive/40 flex items-center justify-center text-destructive font-mono text-xs font-bold mt-0.5">
                            {i + 1}
                          </div>
                          <p className="font-mono text-xs text-foreground/90 leading-relaxed">{action}</p>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Recovery Steps */}
                  <div className="bg-secondary/5 border border-secondary/20 rounded-sm p-4">
                    <h3 className="text-sm font-rajdhani font-bold uppercase mb-4 text-secondary tracking-wider">
                      Recovery Steps
                    </h3>
                    <ul className="space-y-2.5">
                      {(result.response_plan.recovery_steps || []).map((step, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <div className="flex-shrink-0 w-5 h-5 rounded-sm bg-secondary/20 border border-secondary/40 flex items-center justify-center text-secondary font-mono text-xs font-bold mt-0.5">
                            {i + 1}
                          </div>
                          <p className="font-mono text-xs text-foreground/90 leading-relaxed">{step}</p>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Lessons Learned */}
                  <div className="bg-accent/5 border border-accent/20 rounded-sm p-4">
                    <h3 className="text-sm font-rajdhani font-bold uppercase mb-4 text-accent tracking-wider">
                      Lessons Learned
                    </h3>
                    <ul className="space-y-2.5">
                      {(result.response_plan.lessons_learned || []).map((lesson, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <div className="flex-shrink-0 w-5 h-5 rounded-sm bg-accent/20 border border-accent/40 flex items-center justify-center text-accent font-mono text-xs font-bold mt-0.5">
                            {i + 1}
                          </div>
                          <p className="font-mono text-xs text-foreground/90 leading-relaxed">{lesson}</p>
                        </li>
                      ))}
                    </ul>
                  </div>

                </div>
              </div>
            )}

            {/* Prevention Tips */}
            {result.prevention_tips && result.prevention_tips.length > 0 && (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
                <h2 className="text-xl font-rajdhani font-bold uppercase mb-6 text-foreground flex items-center gap-2">
                  <Shield className="w-5 h-5 text-accent" />
                  Prevention Tips
                </h2>
                <ul className="space-y-3">
                  {normalizeTips(result.prevention_tips).map((tip, index) => (
                    <li key={index} className="flex items-start gap-3">
                      <div className="flex-shrink-0 w-2 h-2 rounded-full bg-accent mt-2" />
                      <div className="flex-1">
                        <p className="font-mono text-sm text-foreground">{tip.text}</p>
                        {tip.addresses_step && (
                          <span className="inline-block mt-1 text-xs font-mono px-2 py-0.5 rounded-sm bg-accent/10 border border-accent/20 text-accent">
                            Addresses Step {tip.addresses_step}
                          </span>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Source badge */}
            {result.generation_source && (
              <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
                <BookOpen className="w-3 h-3" />
                Source:{" "}
                <span className={result.generation_source === "llm" ? "text-accent" : "text-secondary"}>
                  {result.generation_source === "llm" ? "AI Generated" : "Curated Fallback Dataset"}
                </span>
                {result.fallback_reason && (
                  <span className="text-muted-foreground/60">({result.fallback_reason})</span>
                )}
              </div>
            )}

          </div>
        )}
      </motion.div>
    </div>
  );
};

export default RansomwareSimulator;
