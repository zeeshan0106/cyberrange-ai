import { motion } from "framer-motion";
import { Shield, Target, Users, Code, Lock, Server } from "lucide-react";
import { Card } from "@/components/ui/card";

export const About = () => {
  return (
    <div className="py-8" data-testid="about-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="flex items-center gap-3 mb-8">
          <Shield className="w-8 h-8 text-primary" />
          <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-primary">
            About CyberRange AI
          </h1>
        </div>

        {/* Introduction Section */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-8 mb-8">
          <h2 className="text-2xl font-rajdhani font-bold uppercase mb-4 text-foreground">
            Practise detection and response before a real incident.
          </h2>
          <p className="text-lg text-foreground/80 leading-relaxed font-mono">
            CyberRange AI is a cybersecurity training platform that generates phishing, ransomware, and multi-stage attack scenarios mapped to MITRE ATT&amp;CK, with interactive quizzes and a progress dashboard.
            Scenarios are produced by a large language model, with a rule-based fallback and structured validation of the output.
            All content is simulated and intended for educational use only.
          </p>
        </div>

        {/* Key Features Grid */}
        <h3 className="text-xl font-rajdhani font-bold uppercase mb-6 text-primary">Core Capabilities</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
          <Card className="bg-black/40 border-white/10 p-6 hover:border-primary/50 transition-all">
            <Target className="w-8 h-8 text-destructive mb-4" />
            <h4 className="text-lg font-rajdhani font-bold uppercase mb-2">Scenario Generation</h4>
            <p className="text-sm text-muted-foreground font-mono">
              Generates phishing emails, ransomware infection chains, and multi-stage attack scenarios on demand using a large language model with a rule-based fallback.
            </p>
          </Card>
          
          <Card className="bg-black/40 border-white/10 p-6 hover:border-primary/50 transition-all">
            <Users className="w-8 h-8 text-accent mb-4" />
            <h4 className="text-lg font-rajdhani font-bold uppercase mb-2">MITRE ATT&amp;CK Mapping</h4>
            <p className="text-sm text-muted-foreground font-mono">
              Techniques in Attack Scenario and Ransomware outputs are validated against the official MITRE ATT&amp;CK Enterprise dataset (858 techniques). Tactic and technique IDs are checked and corrected where needed.
            </p>
          </Card>

          <Card className="bg-black/40 border-white/10 p-6 hover:border-primary/50 transition-all">
            <Code className="w-8 h-8 text-secondary mb-4" />
            <h4 className="text-lg font-rajdhani font-bold uppercase mb-2">Detection &amp; Response Guidance</h4>
            <p className="text-sm text-muted-foreground font-mono">
              Each scenario stage includes detection indicators, containment steps, and a structured incident-response plan mapped to the relevant ATT&amp;CK techniques.
            </p>
          </Card>
        </div>

        {/* Technical Architecture */}
        <div className="bg-secondary/5 border border-secondary/20 rounded-sm p-8 mb-8">
          <h3 className="text-xl font-rajdhani font-bold uppercase mb-6 text-secondary flex items-center gap-2">
            <Server className="w-6 h-6" />
            Under the Hood
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div>
              <h4 className="font-bold text-foreground mb-2 font-mono">Frontend</h4>
              <ul className="list-disc list-inside text-sm text-muted-foreground font-mono space-y-2">
                <li>React 18 with Framer Motion for animations</li>
                <li>Tailwind CSS for responsive UI</li>
                <li>Recharts for dashboard analytics</li>
              </ul>
            </div>
            <div>
              <h4 className="font-bold text-foreground mb-2 font-mono">Backend</h4>
              <ul className="list-disc list-inside text-sm text-muted-foreground font-mono space-y-2">
                <li>FastAPI (Python) for the REST API</li>
                <li>MongoDB with Motor (async driver) for data storage</li>
                <li>LiteLLM-based LLM integration with retry and fallback logic</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Mission Statement */}
        <div className="text-center py-8 border-t border-white/10">
          <Lock className="w-12 h-12 text-primary mx-auto mb-4" />
          <h2 className="text-2xl font-rajdhani font-bold uppercase text-foreground mb-2">
            CyberRange AI
          </h2>
          <p className="text-muted-foreground font-mono max-w-2xl mx-auto">
            All content is simulated and for educational use only. Planned: user accounts and roles, SIEM-style log generation, pretrained phishing classifier, LMS integration.
          </p>
          <p className="text-xs text-muted-foreground/60 font-mono mt-4">
            Educational use only. No real malware or live attack infrastructure is used.
          </p>
        </div>
      </motion.div>
    </div>
  );
};

export default About;
