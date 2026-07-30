import { useState, useEffect } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { LayoutDashboard, Activity, Bug, Zap, Trophy, Users, Shield, Sword } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    fetchStats();
  }, []);
  
  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/dashboard/stats`);
      setStats(response.data);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };
  
  const statCards = [
    {
      icon: Activity,
      label: "Phishing Simulations",
      value: stats?.phishing_sims || 0,
      color: "primary"
    },
    {
      icon: Bug,
      label: "Ransomware Scenarios",
      value: stats?.ransomware_sims || 0,
      color: "destructive"
    },
    {
      icon: Zap,
      label: "Attack Scenarios",
      value: stats?.attack_scenarios || 0,
      color: "accent"
    },
    {
      icon: Users,
      label: "Multiplayer Attacks",
      value: stats?.multiplayer_stats?.total_attacks || 0,
      color: "primary"
    },
  ];
  
  // Calculate defense rate
  const totalAttacks = stats?.multiplayer_stats?.total_attacks || 0;
  const reported = stats?.multiplayer_stats?.reported || 0;
  const defenseRate = totalAttacks > 0 ? Math.round((reported / totalAttacks) * 100) : 0;
  
  return (
    <div className="py-8" data-testid="dashboard-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-3 mb-8">
          <LayoutDashboard className="w-8 h-8 text-primary" />
          <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-primary">
            Dashboard
          </h1>
        </div>
        
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
          {statCards.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                data-testid={`stat-${stat.label.toLowerCase().replace(' ', '-')}`}
              >
                <Card className="bg-black/40 backdrop-blur-md border-white/10 p-6 hover:border-primary/50 transition-all h-full flex flex-col justify-between">
                  <div className="flex items-center justify-between mb-4">
                    <Icon className={`w-8 h-8 text-${stat.color}`} />
                    <div className={`text-4xl font-rajdhani font-bold text-${stat.color}`}>
                      {loading ? "-" : stat.value}
                    </div>
                  </div>
                  <div className="text-sm font-mono text-muted-foreground uppercase">
                    {stat.label}
                  </div>
                </Card>
              </motion.div>
            );
          })}
        </div>

        {/* Multiplayer Section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <Card className="bg-black/40 backdrop-blur-md border-white/10 p-6 col-span-2">
                <h3 className="text-xl font-rajdhani font-bold uppercase mb-6 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-blue-500" /> Multiplayer Defense Stats
                </h3>
                <div className="space-y-6">
                    <div>
                        <div className="flex justify-between mb-2">
                            <span className="text-sm font-mono text-gray-400">Defense Success Rate</span>
                            <span className="text-sm font-bold text-blue-400">{defenseRate}%</span>
                        </div>
                        <Progress value={defenseRate} className="h-2 bg-gray-800" indicatorClassName="bg-blue-500" />
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                        <div className="bg-black/40 p-4 rounded border border-green-500/20">
                            <div className="text-2xl font-bold text-green-500 mb-1">
                                {stats?.multiplayer_stats?.reported || 0}
                            </div>
                            <div className="text-xs text-gray-500 uppercase">Attacks Reported</div>
                        </div>
                        <div className="bg-black/40 p-4 rounded border border-red-500/20">
                            <div className="text-2xl font-bold text-red-500 mb-1">
                                {stats?.multiplayer_stats?.clicked || 0}
                            </div>
                            <div className="text-xs text-gray-500 uppercase">Users Hacked</div>
                        </div>
                    </div>
                </div>
            </Card>

            <Card className="bg-gradient-to-br from-red-950/40 to-black border-red-500/20 p-6">
                <h3 className="text-xl font-rajdhani font-bold uppercase mb-4 flex items-center gap-2 text-red-500">
                    <Sword className="w-5 h-5" /> Red Team Activity
                </h3>
                <div className="space-y-4">
                    <div className="flex justify-between items-center border-b border-white/10 pb-3">
                        <span className="text-sm text-gray-400">Total Attacks Launched</span>
                        <span className="font-mono text-lg">{stats?.multiplayer_stats?.total_attacks || 0}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-white/10 pb-3">
                        <span className="text-sm text-gray-400">Active Campaigns</span>
                        <span className="font-mono text-lg">
                             {(stats?.multiplayer_stats?.total_attacks || 0) - ((stats?.multiplayer_stats?.clicked || 0) + (stats?.multiplayer_stats?.reported || 0))}
                        </span>
                    </div>
                    <p className="text-xs text-gray-500 italic mt-4">
                        "The best defense is a good offense."
                    </p>
                </div>
            </Card>
        </div>
        
        {/* Total Simulations */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6">
          <h2 className="text-2xl font-rajdhani font-bold uppercase mb-4 text-foreground">
            Training Summary
          </h2>
          
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-mono text-muted-foreground mb-2">
                Total Simulations Run
              </div>
              <div className="text-5xl font-rajdhani font-bold text-primary">
                {loading ? "-" : stats?.total_simulations || 0}
              </div>
            </div>
            
            <div className="text-right">
              <div className="text-sm font-mono text-muted-foreground mb-2">
                Training Progress
              </div>
              <div className="text-2xl font-rajdhani font-bold text-secondary">
                {loading ? "-" : `${stats?.training_score || 0} pts`}
              </div>
            </div>
          </div>
        </div>
        
        {/* Empty State */}
        {!loading && stats?.total_simulations === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mt-8 text-center py-16"
          >
            <LayoutDashboard className="w-24 h-24 text-muted-foreground mx-auto mb-4 opacity-30" />
            <p className="text-lg font-mono text-muted-foreground">
              No simulations run yet. Start training to see your progress!
            </p>
          </motion.div>
        )}
      </motion.div>
    </div>
  );
};

export default Dashboard;
