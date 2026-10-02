import { useState, useEffect } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { 
  LayoutDashboard, 
  Trophy, 
  Target, 
  Flame, 
  GraduationCap, 
  TrendingUp, 
  AlertTriangle, 
  Compass, 
  BarChart3, 
  Loader2 
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  Tooltip, 
  CartesianGrid, 
  Cell 
} from "recharts";

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
      console.error("Failed to fetch dashboard stats:", error);
    } finally {
      setLoading(false);
    }
  };

  // Top 5 Non-duplicate stat cards
  const statCards = [
    {
      icon: Trophy,
      label: "Total Score",
      value: stats?.total_score ?? stats?.training_score ?? 0,
      color: "text-secondary",
      borderColor: "border-secondary/30",
      bgColor: "bg-secondary/10"
    },
    {
      icon: GraduationCap,
      label: "Questions Answered",
      value: stats?.questions_answered ?? 0,
      color: "text-primary",
      borderColor: "border-primary/30",
      bgColor: "bg-primary/10"
    },
    {
      icon: Target,
      label: "Overall Accuracy",
      value: `${stats?.overall_accuracy ?? 0}%`,
      color: "text-emerald-400",
      borderColor: "border-emerald-500/30",
      bgColor: "bg-emerald-500/10"
    },
    {
      icon: Flame,
      label: "Current Streak",
      value: stats?.current_streak ?? 0,
      color: "text-destructive",
      borderColor: "border-destructive/30",
      bgColor: "bg-destructive/10"
    },
    {
      icon: LayoutDashboard,
      label: "Simulations Run",
      value: stats?.total_simulations ?? 0,
      color: "text-accent",
      borderColor: "border-accent/30",
      bgColor: "bg-accent/10"
    }
  ];

  // Prepare chart data for Category Accuracy
  const categoryChartData = stats?.category_accuracy
    ? Object.entries(stats.category_accuracy).map(([cat, data]) => ({
        category: cat,
        accuracy: data.accuracy,
        total: data.total,
        answered: data.answered,
        correct: data.correct
      }))
    : [];

  // Simulations by type chart data
  const simulationChartData = stats?.simulations_by_type?.length
    ? stats.simulations_by_type
    : [
        { name: "Phishing", count: stats?.phishing_sims || 0, color: "#00f0ff" },
        { name: "Ransomware", count: stats?.ransomware_sims || 0, color: "#ff003c" },
        { name: "Attack Scenario", count: stats?.attack_scenarios || 0, color: "#fcee0a" }
      ];

  // Score growth over time
  const scoreOverTimeData = stats?.score_over_time || [];

  const SIMULATION_COLORS = ["#00f0ff", "#ff003c", "#fcee0a"];

  return (
    <div className="py-8 space-y-8" data-testid="dashboard-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-8"
      >
        {/* Dashboard Title */}
        <div className="flex items-center gap-3">
          <LayoutDashboard className="w-8 h-8 text-primary" />
          <div>
            <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-primary">
              Executive Cyber Dashboard
            </h1>
            <p className="text-xs font-mono text-muted-foreground mt-0.5">
              Unified real-time metrics across simulations, attack scenarios, and skill training
            </p>
          </div>
        </div>

        {/* Top Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {statCards.map((stat, index) => {
            const Icon = stat.icon;
            return (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                data-testid={`stat-${stat.label.toLowerCase().replace(/\s+/g, '-')}`}
              >
                <Card className={`bg-black/40 backdrop-blur-md border ${stat.borderColor} p-5 hover:border-white/30 transition-all h-full flex flex-col justify-between`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className={`p-2 rounded-sm ${stat.bgColor}`}>
                      <Icon className={`w-5 h-5 ${stat.color}`} />
                    </div>
                    <div className={`text-3xl font-rajdhani font-bold ${stat.color}`}>
                      {loading ? "-" : stat.value}
                    </div>
                  </div>
                  <div className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                    {stat.label}
                  </div>
                </Card>
              </motion.div>
            );
          })}
        </div>

        {/* Recommendations and Insights Card */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Weakest Area Alert */}
          <div className="bg-black/40 backdrop-blur-md border border-amber-500/20 rounded-sm p-5 space-y-2" data-testid="weakest-area-card">
            <div className="flex items-center gap-2 text-amber-400 font-rajdhani font-bold text-sm uppercase">
              <AlertTriangle className="w-4 h-4" />
              Focus & Vulnerability Analysis
            </div>
            <div className="font-mono text-xs text-foreground/90 leading-relaxed">
              {stats?.weakest_area ? (
                <>
                  <span className="text-amber-400 font-bold uppercase">{stats.weakest_area}</span> is currently your lowest-scoring domain (
                  {stats?.category_accuracy?.[stats.weakest_area]?.accuracy ?? 0}% accuracy across{" "}
                  {stats?.category_accuracy?.[stats.weakest_area]?.total ?? 0} attempts).
                </>
              ) : (
                <span className="text-muted-foreground">
                  Complete at least 3 questions in a single training category to unlock domain strength analysis.
                </span>
              )}
            </div>
          </div>

          {/* Recommended Next Action */}
          <div className="bg-black/40 backdrop-blur-md border border-secondary/20 rounded-sm p-5 space-y-2" data-testid="recommended-next-card">
            <div className="flex items-center gap-2 text-secondary font-rajdhani font-bold text-sm uppercase">
              <Compass className="w-4 h-4" />
              Recommended Next Action
            </div>
            <p className="font-mono text-xs text-foreground/90 leading-relaxed">
              {stats?.recommended_next || "Start with Training Mode or run an interactive Phishing Simulation."}
            </p>
          </div>
        </div>

        {/* Visual Analytics Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Chart 1: Simulations Run by Type */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 space-y-4" data-testid="simulations-by-type-chart">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-rajdhani font-bold uppercase text-foreground flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-primary" />
                Simulations Executed by Type
              </h2>
              <span className="text-xs font-mono text-muted-foreground">
                Total: {stats?.total_simulations || 0}
              </span>
            </div>

            <div className="h-[220px] w-full">
              {stats?.total_simulations > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={simulationChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                    <XAxis dataKey="name" stroke="#888888" tick={{ fill: "#888888", fontSize: 11, fontFamily: "monospace" }} />
                    <YAxis stroke="#888888" tick={{ fill: "#888888", fontSize: 11, fontFamily: "monospace" }} allowDecimals={false} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: "#000000ee", borderColor: "#ffffff20", borderRadius: 4, fontFamily: "monospace", fontSize: 12 }}
                      itemStyle={{ color: "#00f0ff" }}
                    />
                    <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                      {simulationChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={SIMULATION_COLORS[index % SIMULATION_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center text-muted-foreground space-y-1">
                  <BarChart3 className="w-8 h-8 opacity-20 text-primary" />
                  <p className="font-mono text-xs">No simulations executed yet</p>
                </div>
              )}
            </div>
          </div>

          {/* Chart 2: Category Training Accuracy */}
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 space-y-4" data-testid="category-accuracy-chart">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-rajdhani font-bold uppercase text-foreground flex items-center gap-2">
                <Target className="w-4 h-4 text-accent" />
                Training Accuracy by Category
              </h2>
              <span className="text-xs font-mono text-muted-foreground">
                Target: 80%+
              </span>
            </div>

            <div className="h-[220px] w-full">
              {categoryChartData.some(d => d.total > 0) ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={categoryChartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                    <XAxis 
                      dataKey="category" 
                      stroke="#888888" 
                      tick={{ fill: "#888888", fontSize: 10, fontFamily: "monospace" }} 
                      tickFormatter={(v) => v.length > 10 ? `${v.slice(0, 8)}..` : v}
                    />
                    <YAxis 
                      stroke="#888888" 
                      domain={[0, 100]} 
                      tick={{ fill: "#888888", fontSize: 11, fontFamily: "monospace" }} 
                      unit="%"
                    />
                    <Tooltip 
                      contentStyle={{ backgroundColor: "#000000ee", borderColor: "#ffffff20", borderRadius: 4, fontFamily: "monospace", fontSize: 12 }}
                      formatter={(val) => [`${val}%`, "Accuracy"]}
                    />
                    <Bar dataKey="accuracy" fill="#10b981" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-center text-muted-foreground space-y-1">
                  <Target className="w-8 h-8 opacity-20 text-accent" />
                  <p className="font-mono text-xs">No training questions answered yet</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Chart 3: Score Growth Over Time */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 space-y-4" data-testid="score-over-time-chart">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-rajdhani font-bold uppercase text-foreground flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-secondary" />
              Cumulative Score Progression Over Time
            </h2>
            <span className="text-xs font-mono text-secondary font-bold">
              Current: {stats?.total_score || 0} pts
            </span>
          </div>

          <div className="h-[200px] w-full">
            {scoreOverTimeData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={scoreOverTimeData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                  <XAxis dataKey="date" stroke="#888888" tick={{ fill: "#888888", fontSize: 10, fontFamily: "monospace" }} />
                  <YAxis stroke="#888888" tick={{ fill: "#888888", fontSize: 11, fontFamily: "monospace" }} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: "#000000ee", borderColor: "#ffffff20", borderRadius: 4, fontFamily: "monospace", fontSize: 12 }}
                    itemStyle={{ color: "#d946ef" }}
                    formatter={(val) => [`${val} pts`, "Cumulative Score"]}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="score" 
                    stroke="#d946ef" 
                    strokeWidth={2.5} 
                    dot={{ fill: "#d946ef", r: 4 }} 
                    activeDot={{ r: 6, fill: "#f0abfc" }} 
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center text-muted-foreground space-y-1">
                <TrendingUp className="w-8 h-8 opacity-20 text-secondary" />
                <p className="font-mono text-xs">Score progression will chart here as you complete questions</p>
              </div>
            )}
          </div>
        </div>

        {/* Global Empty State */}
        {!loading && (stats?.total_simulations === 0 && (stats?.questions_answered === 0 || !stats?.questions_answered)) && (
          <div className="text-center py-8 text-muted-foreground">
            <LayoutDashboard className="w-12 h-12 text-muted-foreground mx-auto mb-2 opacity-20" />
            <p className="font-mono text-xs">
              Welcome to CyberRange AI. Complete training exercises or launch simulations to populate live analytics.
            </p>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default Dashboard;
