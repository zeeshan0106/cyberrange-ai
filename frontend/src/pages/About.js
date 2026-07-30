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
            The Next Generation of Cyber Training
          </h2>
          <p className="text-lg text-foreground/80 leading-relaxed font-mono">
            CyberRange AI is an advanced simulation platform designed to bridge the gap between theoretical knowledge and practical cybersecurity skills. 
            Unlike traditional training methods that rely on static content, our platform generates dynamic, context-aware attack scenarios tailored to specific industries and roles.
            Whether you are a student, an IT professional, or a security analyst, CyberRange AI provides a safe, controlled environment to understand and defend against modern cyber threats.
          </p>
        </div>

        {/* Key Features Grid */}
        <h3 className="text-xl font-rajdhani font-bold uppercase mb-6 text-primary">Core Capabilities</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-12">
          <Card className="bg-black/40 border-white/10 p-6 hover:border-primary/50 transition-all">
            <Target className="w-8 h-8 text-destructive mb-4" />
            <h4 className="text-lg font-rajdhani font-bold uppercase mb-2">Dynamic Simulations</h4>
            <p className="text-sm text-muted-foreground font-mono">
              Generates unique Phishing, Ransomware, and APT scenarios on-the-fly using advanced logic engines and AI.
            </p>
          </Card>
          
          <Card className="bg-black/40 border-white/10 p-6 hover:border-primary/50 transition-all">
            <Users className="w-8 h-8 text-accent mb-4" />
            <h4 className="text-lg font-rajdhani font-bold uppercase mb-2">Role-Based Training</h4>
            <p className="text-sm text-muted-foreground font-mono">
              Adapts content for different roles (HR, Finance, IT Admin) and industries (Healthcare, Finance, Education).
            </p>
          </Card>

          <Card className="bg-black/40 border-white/10 p-6 hover:border-primary/50 transition-all">
            <Code className="w-8 h-8 text-secondary mb-4" />
            <h4 className="text-lg font-rajdhani font-bold uppercase mb-2">MITRE ATT&CK Mapping</h4>
            <p className="text-sm text-muted-foreground font-mono">
              All scenarios are mapped to real-world MITRE ATT&CK techniques (TTPs) for professional-grade learning.
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
                <li>Tailwind CSS for responsive Cyberpunk UI</li>
                <li>Real-time dashboard visualization</li>
              </ul>
            </div>
            <div>
              <h4 className="font-bold text-foreground mb-2 font-mono">Backend</h4>
              <ul className="list-disc list-inside text-sm text-muted-foreground font-mono space-y-2">
                <li>FastAPI (Python) for high-performance API</li>
                <li>MongoDB Async (Motor) for scalable data storage</li>
                <li>Context-aware generation engine</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Mission Statement */}
        <div className="text-center py-8 border-t border-white/10">
          <Lock className="w-12 h-12 text-primary mx-auto mb-4" />
          <h2 className="text-2xl font-rajdhani font-bold uppercase text-foreground mb-2">
            "Train like you fight."
          </h2>
          <p className="text-muted-foreground font-mono max-w-2xl mx-auto">
            Our mission is to democratize advanced cybersecurity training, making it accessible, engaging, and relevant for the defenders of tomorrow.
          </p>
        </div>
      </motion.div>
    </div>
  );
};

export default About;
