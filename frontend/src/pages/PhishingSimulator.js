import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { 
  Mail, 
  AlertTriangle, 
  Eye, 
  Loader2, 
  ShieldAlert, 
  ShieldCheck, 
  Sparkles, 
  CheckCircle2, 
  XCircle, 
  HelpCircle,
  BookOpen
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
      toast.success("Phishing simulation email generated");
    } catch (error) {
      console.error(error);
      toast.error("Failed to generate phishing email");
    } finally {
      setLoading(false);
    }
  };

  const cleanText = (txt) => {
    if (typeof txt !== "string") return txt;
    return txt.replace(/^[\*\-\•\s]+/, "").trim();
  };

  const getHeaderBadge = (status) => {
    switch (status?.toLowerCase()) {
      case "pass":
        return {
          icon: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />,
          style: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
        };
      case "fail":
        return {
          icon: <XCircle className="w-3.5 h-3.5 text-destructive shrink-0" />,
          style: "border-destructive/40 bg-destructive/10 text-destructive"
        };
      case "softfail":
        return {
          icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />,
          style: "border-amber-500/40 bg-amber-500/10 text-amber-400"
        };
      default:
        return {
          icon: <HelpCircle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />,
          style: "border-white/20 bg-white/5 text-muted-foreground"
        };
    }
  };

  const getTriggerColor = (trigger) => {
    switch (trigger?.toLowerCase()) {
      case "urgency":
        return "border-destructive/30 bg-destructive/10 text-destructive";
      case "authority":
        return "border-purple-500/30 bg-purple-500/10 text-purple-400";
      case "fear":
        return "border-amber-500/30 bg-amber-500/10 text-amber-400";
      case "curiosity":
        return "border-sky-500/30 bg-sky-500/10 text-sky-400";
      case "reward":
        return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
      case "familiarity":
        return "border-secondary/30 bg-secondary/10 text-secondary";
      default:
        return "border-white/20 bg-white/5 text-muted-foreground";
    }
  };

  const isStructuredFlag = (flag) => typeof flag === "object" && flag !== null && flag.flag;

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

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Configuration Panel */}
          <div className="lg:col-span-4 bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 space-y-6">
            <h2 className="text-xl font-rajdhani font-bold uppercase text-foreground">
              Simulation Configuration
            </h2>

            <div className="space-y-6">
              <div>
                <Label htmlFor="role" className="text-sm font-mono text-muted-foreground mb-2 block">
                  Target Role
                </Label>
                <Select
                  value={config.target_role}
                  onValueChange={(value) => setConfig({ ...config, target_role: value })}
                >
                  <SelectTrigger id="role" data-testid="select-role" className="bg-black/50 border-white/20 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-black border-white/20">
                    <SelectItem value="Employee">Employee</SelectItem>
                    <SelectItem value="HR">HR Specialist</SelectItem>
                    <SelectItem value="Finance">Finance / Accounting</SelectItem>
                    <SelectItem value="Student">Student / Academic</SelectItem>
                    <SelectItem value="Admin">IT / System Admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="difficulty" className="text-sm font-mono text-muted-foreground mb-2 block">
                  Difficulty Level
                </Label>
                <Select
                  value={config.difficulty}
                  onValueChange={(value) => setConfig({ ...config, difficulty: value })}
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
                  Industry Vertical
                </Label>
                <Select
                  value={config.industry}
                  onValueChange={(value) => setConfig({ ...config, industry: value })}
                >
                  <SelectTrigger id="industry" data-testid="select-industry" className="bg-black/50 border-white/20 font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-black border-white/20">
                    <SelectItem value="IT">IT & Technology</SelectItem>
                    <SelectItem value="Banking">Banking & Financial Services</SelectItem>
                    <SelectItem value="Healthcare">Healthcare & Hospitals</SelectItem>
                    <SelectItem value="Education">Education & Universities</SelectItem>
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
                    Simulating...
                  </>
                ) : (
                  "Generate Phishing Simulation"
                )}
              </Button>
            </div>
          </div>

          {/* Email Preview & Threat Breakdown */}
          <div className="lg:col-span-8 space-y-6">
            {result ? (
              <div className="space-y-6" data-testid="phishing-result">

                {/* Email Client Preview Card */}
                <div className="bg-black/50 backdrop-blur-md border border-white/15 rounded-sm overflow-hidden shadow-2xl" data-testid="email-client-preview">
                  {/* Email Client Window Header */}
                  <div className="bg-white/5 border-b border-white/10 px-5 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full bg-destructive/60" />
                      <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                      <div className="w-3 h-3 rounded-full bg-emerald-500/60" />
                      <span className="text-xs font-mono text-muted-foreground ml-2">Inbox Preview — Training Simulation Only</span>
                    </div>
                    <span className="text-xs font-mono px-2 py-0.5 rounded-sm bg-destructive/20 text-destructive border border-destructive/30 font-bold uppercase">
                      Suspicious
                    </span>
                  </div>

                  {/* Email Headers Section */}
                  <div className="p-6 bg-black/40 border-b border-white/10 space-y-2.5 font-mono text-xs">
                    {/* From */}
                    <div className="flex items-start gap-2">
                      <span className="w-20 text-muted-foreground uppercase tracking-wider shrink-0 font-bold">From:</span>
                      <span className="text-foreground">
                        <span className="font-semibold text-primary">{result.sender_name || "Notification Gateway"}</span>{" "}
                        <span className="text-muted-foreground">&lt;{result.sender_email || `security-alerts@${config.industry.toLowerCase()}-portal.example`}&gt;</span>
                      </span>
                    </div>

                    {/* Reply-To (if available and different) */}
                    {result.reply_to_email && (
                      <div className="flex items-start gap-2">
                        <span className="w-20 text-destructive uppercase tracking-wider shrink-0 font-bold">Reply-To:</span>
                        <span className="text-destructive-foreground font-semibold">
                          &lt;{result.reply_to_email}&gt;
                        </span>
                      </div>
                    )}

                    {/* To */}
                    <div className="flex items-start gap-2">
                      <span className="w-20 text-muted-foreground uppercase tracking-wider shrink-0 font-bold">To:</span>
                      <span className="text-foreground">
                        <span className="font-semibold">{result.recipient_name || config.target_role}</span>{" "}
                        <span className="text-muted-foreground">&lt;{(result.recipient_name ? result.recipient_name.toLowerCase().replace(/[^a-z0-9]/g, '.') : config.target_role.toLowerCase())}@{config.industry.toLowerCase()}-enterprise.example&gt;</span>
                      </span>
                    </div>

                    {/* Date */}
                    {result.date_sent && (
                      <div className="flex items-start gap-2">
                        <span className="w-20 text-muted-foreground uppercase tracking-wider shrink-0 font-bold">Date:</span>
                        <span className="text-muted-foreground">{result.date_sent}</span>
                      </div>
                    )}

                    {/* Subject */}
                    <div className="flex items-start gap-2 pt-2 border-t border-white/5">
                      <span className="w-20 text-muted-foreground uppercase tracking-wider shrink-0 font-bold">Subject:</span>
                      <span className="text-foreground font-bold text-sm font-rajdhani uppercase tracking-wide text-primary">
                        {cleanText(result.subject)}
                      </span>
                    </div>
                  </div>

                  {/* Email Body Content */}
                  <div className="p-6 bg-black/60 space-y-4">
                    <div className="font-mono text-sm text-foreground/95 whitespace-pre-wrap leading-relaxed">
                      {result.body}
                    </div>

                    {/* Plaintext Safe Link Container (Never a clickable <a> anchor for safety!) */}
                    {(result.link_display_text || result.link_url) && (
                      <div className="mt-4 p-3.5 bg-white/[0.03] border border-white/10 rounded-sm space-y-1.5" data-testid="email-link-box">
                        <div className="font-mono text-sm text-accent break-all select-all">
                          {result.link_display_text || result.link_url}
                        </div>
                        {result.link_url && (
                          <div className="text-xs font-mono text-muted-foreground/90 break-all pt-1 border-t border-white/5">
                            <span className="text-destructive font-semibold">Link destination:</span>{" "}
                            <span className="text-destructive-foreground/90 font-mono">{result.link_url}</span>{" "}
                            <span className="text-muted-foreground/60">(Disabled for training safety)</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                {/* Header Authentication Analysis Block */}
                {result.header_analysis && (
                  <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 space-y-4" data-testid="header-analysis-block">
                    <h3 className="text-base font-rajdhani font-bold uppercase text-foreground flex items-center gap-2">
                      <ShieldCheck className="w-4 h-4 text-primary" />
                      Email Header Authentication Analysis
                    </h3>

                    <div className="grid grid-cols-3 gap-3">
                      {["SPF", "DKIM", "DMARC"].map((proto) => {
                        const status = result.header_analysis[proto.toLowerCase()] || "none";
                        const badge = getHeaderBadge(status);
                        return (
                          <div key={proto} className={`p-3 rounded-sm border flex items-center justify-between font-mono text-xs ${badge.style}`}>
                            <span className="font-bold">{proto}</span>
                            <div className="flex items-center gap-1 uppercase font-bold">
                              {badge.icon}
                              <span>{status}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {result.header_analysis.notes && (
                      <p className="text-xs font-mono text-muted-foreground leading-relaxed bg-white/[0.02] p-3 rounded-sm border border-white/5">
                        <span className="text-foreground font-semibold">Technical Evaluation:</span> {cleanText(result.header_analysis.notes)}
                      </p>
                    )}
                  </div>
                )}

                {/* Red Flags Breakdown */}
                {result.red_flags && result.red_flags.length > 0 && (
                  <div className="bg-black/40 backdrop-blur-md border border-destructive/20 rounded-sm p-6 space-y-4" data-testid="red-flags-section">
                    <h3 className="text-base font-rajdhani font-bold uppercase text-destructive flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Detected Red Flags ({result.red_flags.length})
                    </h3>

                    <div className="space-y-3">
                      {result.red_flags.map((item, idx) => {
                        if (isStructuredFlag(item)) {
                          return (
                            <div key={idx} className="bg-destructive/5 border border-destructive/20 rounded-sm p-3.5 space-y-2 font-mono text-xs">
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-destructive uppercase tracking-wide flex items-center gap-1.5">
                                  <span className="w-1.5 h-1.5 rounded-full bg-destructive" />
                                  {cleanText(item.flag)}
                                </span>
                              </div>
                              {item.evidence && (
                                <div className="bg-black/60 p-2 rounded-sm border border-destructive/20 text-destructive-foreground break-all">
                                  <span className="text-muted-foreground text-[10px] uppercase block mb-0.5">Evidence in Email:</span>
                                  <code className="font-bold text-foreground">"{item.evidence}"</code>
                                </div>
                              )}
                              {item.explanation && (
                                <p className="text-muted-foreground leading-relaxed">
                                  {cleanText(item.explanation)}
                                </p>
                              )}
                            </div>
                          );
                        } else {
                          // Legacy string format fallback
                          return (
                            <div key={idx} className="bg-destructive/5 border border-destructive/20 rounded-sm p-2.5 font-mono text-xs text-destructive-foreground flex items-start gap-2">
                              <AlertTriangle className="w-3.5 h-3.5 text-destructive shrink-0 mt-0.5" />
                              <span>{cleanText(String(item))}</span>
                            </div>
                          );
                        }
                      })}
                    </div>
                  </div>
                )}

                {/* Psychological Triggers */}
                {result.psychological_triggers && result.psychological_triggers.length > 0 && (
                  <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 space-y-3" data-testid="triggers-section">
                    <h3 className="text-base font-rajdhani font-bold uppercase text-foreground flex items-center gap-2">
                      <Sparkles className="w-4 h-4 text-secondary" />
                      Psychological Manipulation Vectors
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {result.psychological_triggers.map((trigger, idx) => (
                        <div key={idx} className={`p-3 rounded-sm border font-mono text-xs space-y-1 ${getTriggerColor(trigger.trigger)}`}>
                          <div className="font-bold uppercase tracking-wider">
                            Vector: {trigger.trigger}
                          </div>
                          {trigger.where_used && (
                            <div className="text-muted-foreground text-[11px]">
                              Used in: <span className="text-foreground font-medium">"{trigger.where_used}"</span>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Safe Defender Response Steps */}
                {result.safe_response && result.safe_response.length > 0 && (
                  <div className="bg-black/40 backdrop-blur-md border border-accent/20 rounded-sm p-6 space-y-3" data-testid="safe-response-section">
                    <h3 className="text-base font-rajdhani font-bold uppercase text-accent flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4" />
                      Recommended Safe Response Actions
                    </h3>
                    <div className="space-y-2.5">
                      {result.safe_response.map((step, idx) => (
                        <div key={idx} className="flex items-start gap-3 bg-accent/5 border border-accent/20 p-3 rounded-sm font-mono text-xs">
                          <div className="w-5 h-5 rounded-sm bg-accent/20 border border-accent/40 flex items-center justify-center text-accent font-bold shrink-0">
                            {idx + 1}
                          </div>
                          <p className="text-foreground/90 leading-relaxed pt-0.5">{cleanText(step)}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Educational Analysis Toggle Card */}
                {result.analysis && (
                  <div className="space-y-3">
                    <Button
                      onClick={() => setShowAnalysis(!showAnalysis)}
                      data-testid="reveal-analysis-btn"
                      variant="outline"
                      className="w-full border-accent text-accent hover:bg-accent/10 rounded-sm font-rajdhani uppercase tracking-widest font-bold"
                    >
                      <Eye className="mr-2 h-4 w-4" />
                      {showAnalysis ? "Hide Educational Analysis" : "Reveal Educational Threat Analysis"}
                    </Button>

                    {showAnalysis && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        className="bg-accent/10 border border-accent/30 rounded-sm p-5 space-y-2"
                        data-testid="analysis-section"
                      >
                        <div className="text-xs font-mono text-accent font-bold uppercase tracking-wider">
                          Simulation Learning Notes:
                        </div>
                        <p className="text-sm font-mono text-foreground leading-relaxed whitespace-pre-wrap">
                          {cleanText(result.analysis)}
                        </p>
                      </motion.div>
                    )}
                  </div>
                )}

                {/* Source Badge */}
                {result.generation_source && (
                  <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground pt-2">
                    <BookOpen className="w-3.5 h-3.5" />
                    <span>Generation Source:</span>
                    <span className={result.generation_source === "llm" ? "text-accent font-bold" : "text-secondary font-bold"}>
                      {result.generation_source === "llm" ? "AI Generated Model" : "Curated Fallback Engine"}
                    </span>
                    {result.fallback_reason && (
                      <span className="text-muted-foreground/60">({result.fallback_reason})</span>
                    )}
                  </div>
                )}

              </div>
            ) : (
              <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-12 flex flex-col items-center justify-center min-h-[380px] text-center text-muted-foreground space-y-3">
                <Mail className="w-16 h-16 opacity-30 text-primary" />
                <h3 className="font-rajdhani font-bold text-lg uppercase text-foreground">No Simulation Generated Yet</h3>
                <p className="font-mono text-xs max-w-sm">
                  Select your target role, difficulty level, and industry on the left, then click Generate to create an interactive training scenario.
                </p>
              </div>
            )}
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default PhishingSimulator;
