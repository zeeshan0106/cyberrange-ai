import { Link, useLocation } from "react-router-dom";
import { Shield, Activity, Bug, Zap, GraduationCap, LayoutDashboard, Info, Users } from "lucide-react";

export const Layout = ({ children }) => {
  const location = useLocation();
  
  const navItems = [
    { path: "/", label: "Home", icon: Shield },
    { path: "/phishing", label: "Phishing", icon: Activity },
    { path: "/ransomware", label: "Ransomware", icon: Bug },
    { path: "/attack-scenario", label: "Attack Scenario", icon: Zap },
    { path: "/training", label: "Training", icon: GraduationCap },
    { path: "/multiplayer", label: "Multiplayer", icon: Users },
    { path: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { path: "/about", label: "About", icon: Info },
  ];
  
  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="border-b border-white/10 bg-black/40 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <Link to="/" className="flex items-center gap-3" data-testid="logo-link">
              <Shield className="w-8 h-8 text-primary" />
              <span className="text-2xl font-rajdhani font-bold tracking-wider uppercase text-primary">
                CyberRange AI
              </span>
            </Link>
            
            <div className="flex items-center gap-2">
              {navItems.slice(1).map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    data-testid={`nav-${item.label.toLowerCase().replace(' ', '-')}`}
                    className={`flex items-center gap-2 px-4 py-2 rounded-sm font-rajdhani font-semibold uppercase tracking-wider text-sm border transition-all ${
                      isActive
                        ? "bg-primary/10 border-primary text-primary cyber-glow"
                        : "border-white/10 text-white/70 hover:text-primary hover:border-primary/50"
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      </nav>
      
      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {children}
      </main>
      
      {/* Footer Warning */}
      <div className="fixed bottom-0 left-0 right-0 bg-destructive/20 border-t border-destructive/50 backdrop-blur-sm py-2 px-6 z-30">
        <p className="text-center text-xs font-mono text-destructive-foreground">
          ⚠️ SIMULATION ONLY - All content is for educational cybersecurity training purposes
        </p>
      </div>
    </div>
  );
};

export default Layout;
