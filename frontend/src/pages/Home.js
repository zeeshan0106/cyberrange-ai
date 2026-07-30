import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Activity, Bug, Zap, GraduationCap, ArrowRight, Users } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Home = () => {
  const features = [
    {
      icon: Activity,
      title: "Phishing Simulator",
      description: "Generate realistic phishing emails with analysis and red flags",
      path: "/phishing",
      color: "primary"
    },
    {
      icon: Bug,
      title: "Ransomware Simulator",
      description: "Explore ransomware attack patterns with MITRE ATT&CK mapping",
      path: "/ransomware",
      color: "destructive"
    },
    {
      icon: Zap,
      title: "Attack Scenarios",
      description: "Full cyber attack storylines with timeline visualization",
      path: "/attack-scenario",
      color: "accent"
    },
    {
      icon: GraduationCap,
      title: "Training Mode",
      description: "Interactive Q&A with scoring and instant feedback",
      path: "/training",
      color: "secondary"
    },
    {
      icon: Users,
      title: "Multiplayer Arena",
      description: "Red Team vs Blue Team: Launch and Defend against attacks in real-time",
      path: "/multiplayer",
      color: "primary"
    },
  ];
  
  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="relative min-h-[60vh] flex items-center justify-center"
        data-testid="hero-section"
      >
        <div className="absolute inset-0 bg-gradient-to-b from-primary/10 to-transparent opacity-30" />
        <div className="relative z-10 text-center max-w-4xl mx-auto px-6">
          <motion.div
            initial={{ scale: 0.9 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.5 }}
            className="mb-6"
          >
            <Shield className="w-24 h-24 text-primary mx-auto mb-6" />
          </motion.div>
          
          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-rajdhani font-bold uppercase tracking-wider text-primary mb-6">
            CyberRange AI
          </h1>
          
          <p className="text-lg sm:text-xl text-foreground/80 mb-8 max-w-2xl mx-auto">
            LLM-powered cybersecurity training simulator. Generate realistic phishing emails, ransomware scenarios, and full attack timelines for hands-on security training.
          </p>
          
          <div className="flex flex-wrap gap-4 justify-center">
            <Link to="/phishing" data-testid="get-started-btn">
              <Button className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest px-8 py-6 text-lg cyber-glow">
                Get Started
                <ArrowRight className="ml-2 w-5 h-5" />
              </Button>
            </Link>
            <Link to="/dashboard" data-testid="view-dashboard-btn">
              <Button variant="outline" className="border-primary text-primary hover:bg-primary/10 rounded-sm font-rajdhani uppercase tracking-widest px-8 py-6 text-lg">
                View Dashboard
              </Button>
            </Link>
          </div>
        </div>
      </motion.div>
      
      {/* Features Grid */}
      <div className="py-16" data-testid="features-grid">
        <h2 className="text-3xl font-rajdhani font-bold uppercase text-center mb-12 text-primary">
          Training Modules
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <motion.div
                key={feature.path}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1, duration: 0.5 }}
                data-testid={`feature-${feature.title.toLowerCase().replace(' ', '-')}`}
              >
                <Link to={feature.path}>
                  <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-8 hover:border-primary/50 transition-all group relative overflow-hidden h-full">
                    <div className={`absolute top-0 left-0 w-1 h-full bg-${feature.color} opacity-50`} />
                    
                    <Icon className={`w-12 h-12 text-${feature.color} mb-4 group-hover:scale-110 transition-all`} />
                    
                    <h3 className="text-2xl font-rajdhani font-bold uppercase mb-3 text-foreground group-hover:text-primary transition-colors">
                      {feature.title}
                    </h3>
                    
                    <p className="text-muted-foreground mb-4">
                      {feature.description}
                    </p>
                    
                    <div className="flex items-center gap-2 text-primary font-mono text-sm group-hover:gap-4 transition-all">
                      Launch Module <ArrowRight className="w-4 h-4" />
                    </div>
                  </div>
                </Link>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default Home;
