import { useState, useEffect, useRef } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { Users, Shield, Sword, Send, AlertTriangle, RefreshCw, Mail } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "http://localhost:8000";
const API = `${BACKEND_URL}/api`;

export const MultiplayerMode = () => {
  const [role, setRole] = useState(null); // 'red' or 'blue'

  return (
    <div className="py-8 min-h-screen">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center gap-3 mb-8">
          <Users className="w-8 h-8 text-primary" />
          <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-primary">
            Multiplayer Arena
          </h1>
        </div>

        {!role ? (
          <RoleSelection setRole={setRole} />
        ) : role === 'red' ? (
          <RedTeamView onBack={() => setRole(null)} />
        ) : (
          <BlueTeamView onBack={() => setRole(null)} />
        )}
      </motion.div>
    </div>
  );
};

const RoleSelection = ({ setRole }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-4xl mx-auto mt-12">
      <motion.div whileHover={{ scale: 1.02 }} className="cursor-pointer" onClick={() => setRole('red')}>
        <Card className="h-full bg-red-950/20 border-red-500/50 hover:border-red-500 transition-all">
          <CardHeader className="text-center">
            <Sword className="w-16 h-16 text-red-500 mx-auto mb-4" />
            <CardTitle className="text-3xl font-rajdhani text-red-500">Red Team</CardTitle>
            <CardDescription className="text-lg">The Attacker</CardDescription>
          </CardHeader>
          <CardContent className="text-center text-muted-foreground">
            <p>Your goal is to craft convincing phishing emails and social engineering attacks to compromise the Blue Team.</p>
            <Button className="mt-6 bg-red-600 hover:bg-red-700 w-full">Join Red Team</Button>
          </CardContent>
        </Card>
      </motion.div>

      <motion.div whileHover={{ scale: 1.02 }} className="cursor-pointer" onClick={() => setRole('blue')}>
        <Card className="h-full bg-blue-950/20 border-blue-500/50 hover:border-blue-500 transition-all">
          <CardHeader className="text-center">
            <Shield className="w-16 h-16 text-blue-500 mx-auto mb-4" />
            <CardTitle className="text-3xl font-rajdhani text-blue-500">Blue Team</CardTitle>
            <CardDescription className="text-lg">The Defender</CardDescription>
          </CardHeader>
          <CardContent className="text-center text-muted-foreground">
            <p>Your goal is to monitor incoming communications, identify threats, and report them without getting compromised.</p>
            <Button className="mt-6 bg-blue-600 hover:bg-blue-700 w-full">Join Blue Team</Button>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};

const RedTeamView = ({ onBack }) => {
  const [formData, setFormData] = useState({
    subject: "",
    body: "",
    link: "http://malicious-site.com/login"
  });
  const [loading, setLoading] = useState(false);

  const handleSend = async () => {
    if (!formData.subject || !formData.body) {
      toast.error("Please fill in all fields");
      return;
    }

    setLoading(true);
    try {
      await axios.post(`${API}/multiplayer/send`, formData);
      toast.success("Attack Sent Successfully!");
      setFormData({ ...formData, subject: "", body: "" });
    } catch (error) {
      console.error(error);
      toast.error("Failed to send attack");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <Button variant="ghost" onClick={onBack} className="mb-4 text-muted-foreground hover:text-white">← Change Role</Button>
      <Card className="bg-black/40 border-red-500/30">
        <CardHeader>
          <CardTitle className="text-red-500 flex items-center gap-2">
            <Sword className="w-5 h-5" /> Attack Console
          </CardTitle>
          <CardDescription>Craft a phishing email to target the Blue Team.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <Label>Subject Line</Label>
            <Input 
              value={formData.subject}
              onChange={(e) => setFormData({...formData, subject: e.target.value})}
              placeholder="e.g. Urgent: Account Suspension"
              className="bg-black/50 border-white/10"
            />
          </div>
          <div>
            <Label>Email Body</Label>
            <Textarea 
              value={formData.body}
              onChange={(e) => setFormData({...formData, body: e.target.value})}
              placeholder="Write your phishing message here..."
              className="min-h-[150px] bg-black/50 border-white/10"
            />
          </div>
          <div>
            <Label>Malicious Link</Label>
            <Input 
              value={formData.link}
              onChange={(e) => setFormData({...formData, link: e.target.value})}
              className="bg-black/50 border-white/10 text-red-400 font-mono"
            />
          </div>
          <Button 
            onClick={handleSend} 
            disabled={loading}
            className="w-full bg-red-600 hover:bg-red-700 text-white"
          >
            {loading ? "Sending..." : "Launch Attack"} <Send className="w-4 h-4 ml-2" />
          </Button>
        </CardContent>
      </Card>
    </div>
  );
};

const BlueTeamView = ({ onBack }) => {
  const [emails, setEmails] = useState([]);
  const [hackedOpen, setHackedOpen] = useState(false);
  const [selectedEmail, setSelectedEmail] = useState(null);
  const prevEmailsLengthRef = useRef(0);

  const fetchEmails = async () => {
    try {
      const res = await axios.get(`${API}/multiplayer/inbox`);
      const currentLength = res.data.length;
      const prevLength = prevEmailsLengthRef.current;
      
      // Check for new emails to show toast alert
      if (currentLength > prevLength && prevLength > 0) {
          const newEmailCount = currentLength - prevLength;
          toast.info(`⚠️ Alert: ${newEmailCount} new message(s) received!`, {
            style: { border: '1px solid #facc15', color: '#facc15' }
          });
      }
      
      prevEmailsLengthRef.current = currentLength;
      setEmails(res.data);
    } catch (error) {
      console.error("Polling error", error);
    }
  };

  // Poll every 3 seconds
  useEffect(() => {
    // Initial fetch
    fetchEmails();
    
    const interval = setInterval(fetchEmails, 1000);
    return () => clearInterval(interval);
  }, []);


  const handleLinkClick = async (id) => {
    setHackedOpen(true);
    try {
      await axios.post(`${API}/multiplayer/resolve?attack_id=${id}&action=clicked`);
    } catch (e) {}
  };

  const handleReport = async (id) => {
    toast.success("Attack Reported! You are safe.");
    try {
      await axios.post(`${API}/multiplayer/resolve?attack_id=${id}&action=reported`);
      fetchEmails(); // Refresh status
    } catch (e) {}
  };

  return (
    <div className="max-w-4xl mx-auto">
      <Button variant="ghost" onClick={onBack} className="mb-4 text-muted-foreground hover:text-white">← Change Role</Button>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Inbox List */}
        <div className="md:col-span-1 space-y-3">
          <div className="flex items-center justify-between mb-2">
            <h3 className="font-bold text-blue-400">Inbox ({emails.filter(e => e.status === 'pending').length})</h3>
            <RefreshCw className="w-4 h-4 text-muted-foreground animate-spin-slow" />
          </div>
          <div className="space-y-2 h-[600px] overflow-y-auto pr-2">
            {emails.map((email) => (
              <div 
                key={email.id}
                onClick={() => setSelectedEmail(email)}
                className={`p-3 rounded-md border cursor-pointer transition-colors ${
                  selectedEmail?.id === email.id 
                    ? "bg-blue-900/30 border-blue-500" 
                    : "bg-black/40 border-white/10 hover:bg-white/5"
                } ${email.status !== 'pending' ? 'opacity-50' : ''}`}
              >
                <div className="flex justify-between items-start mb-1">
                  <span className="font-bold text-sm truncate w-full">{email.subject}</span>
                  {email.status !== 'pending' && (
                     <Badge variant="outline" className="text-[10px] h-5">{email.status}</Badge>
                  )}
                </div>
                <p className="text-xs text-muted-foreground line-clamp-2">{email.body}</p>
                <span className="text-[10px] text-muted-foreground mt-2 block">
                  {new Date(email.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
            {emails.length === 0 && (
              <div className="text-center text-muted-foreground text-sm py-10">
                No emails yet...
              </div>
            )}
          </div>
        </div>

        {/* Email Reading Pane */}
        <div className="md:col-span-2">
          {selectedEmail ? (
            <Card className="h-full bg-black/60 border-white/10">
              <CardHeader className="border-b border-white/10 pb-4">
                <div className="flex justify-between items-start">
                  <div>
                    <CardTitle className="text-xl">{selectedEmail.subject}</CardTitle>
                    <CardDescription className="mt-1">From: unknown-sender@internet.com</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button 
                      variant="destructive" 
                      size="sm"
                      onClick={() => handleReport(selectedEmail.id)}
                      disabled={selectedEmail.status !== 'pending'}
                    >
                      <Shield className="w-4 h-4 mr-2" /> Report Phishing
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="pt-6">
                <div className="prose prose-invert max-w-none whitespace-pre-wrap text-sm text-gray-300">
                  {selectedEmail.body}
                </div>
                
                <div className="mt-8 p-4 bg-yellow-950/10 border border-yellow-500/20 rounded-md">
                  <p className="text-xs text-yellow-500 mb-2 font-mono uppercase">Attachment / Link:</p>
                  <button 
                    onClick={() => handleLinkClick(selectedEmail.id)}
                    className="text-blue-400 underline hover:text-blue-300 text-sm break-all text-left"
                    disabled={selectedEmail.status !== 'pending'}
                  >
                    {selectedEmail.link}
                  </button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-muted-foreground border border-dashed border-white/10 rounded-lg bg-black/20">
              <Mail className="w-12 h-12 mb-4 opacity-20" />
              <p>Select an email to read</p>
            </div>
          )}
        </div>
      </div>

      {/* Hacked Modal */}
      <AlertDialog open={hackedOpen} onOpenChange={setHackedOpen}>
        <AlertDialogContent className="bg-red-950 border-red-500 text-white">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-3xl font-bold text-red-500 flex items-center gap-2">
              <AlertTriangle className="w-8 h-8" /> YOU HAVE BEEN HACKED!
            </AlertDialogTitle>
            <AlertDialogDescription className="text-red-200 text-lg">
              You clicked on a malicious link sent by the Red Team. 
              In a real scenario, this could have led to ransomware infection or credential theft.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogAction className="bg-red-600 hover:bg-red-700 text-white border-none">
              I Understand
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};
