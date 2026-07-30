import { useState } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { GraduationCap, CheckCircle, XCircle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export const TrainingMode = () => {
  const [scenarioType, setScenarioType] = useState("Phishing");
  const [question, setQuestion] = useState(null);
  const [selectedAnswer, setSelectedAnswer] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [score, setScore] = useState(0);
  
  const handleGenerateQuestion = async () => {
    setLoading(true);
    setSelectedAnswer(null);
    setResult(null);
    try {
      const response = await axios.post(`${API}/training/question`, {
        scenario_type: scenarioType
      });
      setQuestion(response.data);
      toast.success("New question generated");
    } catch (error) {
      console.error(error);
      toast.error("Failed to generate question");
    } finally {
      setLoading(false);
    }
  };
  
  const handleSubmitAnswer = async () => {
    if (!selectedAnswer) {
      toast.error("Please select an answer");
      return;
    }
    
    setLoading(true);
    try {
      const response = await axios.post(`${API}/training/answer`, {
        question_id: question.id,
        user_answer: selectedAnswer
      });
      setResult(response.data);
      if (response.data.correct) {
        setScore(score + response.data.score_gained);
        toast.success(`Correct! +${response.data.score_gained} points`);
      } else {
        toast.error("Incorrect answer");
      }
    } catch (error) {
      console.error(error);
      toast.error("Failed to submit answer");
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="py-8" data-testid="training-mode-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <GraduationCap className="w-8 h-8 text-secondary" />
            <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-secondary">
              Training Mode
            </h1>
          </div>
          
          <div className="bg-secondary/20 border border-secondary rounded-sm px-6 py-3" data-testid="score-display">
            <div className="text-xs font-mono text-secondary uppercase">Total Score</div>
            <div className="text-3xl font-rajdhani font-bold text-secondary">{score}</div>
          </div>
        </div>
        
        {/* Configuration */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 mb-6">
          <div className="flex items-end gap-4">
            <div className="flex-1">
              <Label htmlFor="scenario" className="text-sm font-mono text-muted-foreground mb-2 block">
                Question Type
              </Label>
              <Select
                value={scenarioType}
                onValueChange={setScenarioType}
              >
                <SelectTrigger id="scenario" data-testid="select-scenario-type" className="bg-black/50 border-white/20 font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-black border-white/20">
                  <SelectItem value="Phishing">Phishing</SelectItem>
                  <SelectItem value="Ransomware">Ransomware</SelectItem>
                  <SelectItem value="General Security">General Security</SelectItem>
                  <SelectItem value="Incident Response">Incident Response</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <Button
              onClick={handleGenerateQuestion}
              disabled={loading}
              data-testid="generate-question-btn"
              className="bg-secondary text-secondary-foreground hover:bg-secondary/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Loading...
                </>
              ) : (
                "New Question"
              )}
            </Button>
          </div>
        </div>
        
        {/* Question */}
        {question && (
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 mb-6" data-testid="question-section">
            <h2 className="text-xl font-rajdhani font-bold mb-6 text-foreground">
              {question.question}
            </h2>
            
            <RadioGroup value={selectedAnswer} onValueChange={setSelectedAnswer}>
              <div className="space-y-3">
                {question.options.map((option, index) => {
                  const letter = String.fromCharCode(65 + index);
                  return (
                    <div
                      key={index}
                      className={`flex items-center space-x-3 p-4 rounded-sm border transition-all ${
                        selectedAnswer === letter
                          ? "bg-primary/10 border-primary"
                          : "bg-black/60 border-white/20 hover:border-white/40"
                      }`}
                    >
                      <RadioGroupItem
                        value={letter}
                        id={`option-${letter}`}
                        data-testid={`option-${letter}`}
                        className="border-white/40"
                      />
                      <Label
                        htmlFor={`option-${letter}`}
                        className="flex-1 cursor-pointer font-mono text-sm text-foreground"
                      >
                        <span className="font-bold text-primary mr-2">{letter}.</span>
                        {option}
                      </Label>
                    </div>
                  );
                })}
              </div>
            </RadioGroup>
            
            {!result && (
              <Button
                onClick={handleSubmitAnswer}
                disabled={loading || !selectedAnswer}
                data-testid="submit-answer-btn"
                className="w-full mt-6 bg-accent text-accent-foreground hover:bg-accent/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
              >
                Submit Answer
              </Button>
            )}
          </div>
        )}
        
        {/* Result */}
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`bg-black/40 backdrop-blur-md border rounded-sm p-6 ${
              result.correct
                ? "border-accent"
                : "border-destructive"
            }`}
            data-testid="result-section"
          >
            <div className="flex items-center gap-3 mb-4">
              {result.correct ? (
                <>
                  <CheckCircle className="w-6 h-6 text-accent" />
                  <h3 className="text-xl font-rajdhani font-bold uppercase text-accent">
                    Correct Answer!
                  </h3>
                </>
              ) : (
                <>
                  <XCircle className="w-6 h-6 text-destructive" />
                  <h3 className="text-xl font-rajdhani font-bold uppercase text-destructive">
                    Incorrect Answer
                  </h3>
                </>
              )}
            </div>
            
            <div className="bg-black/60 border border-white/20 rounded-sm p-4 mb-4">
              <div className="text-xs font-mono text-muted-foreground mb-2">EXPLANATION:</div>
              <p className="text-sm font-mono text-foreground">{result.explanation}</p>
            </div>
            
            {question && (
              <div className="bg-accent/10 border border-accent/30 rounded-sm p-4 mb-4">
                <div className="text-xs font-mono text-accent mb-2">CORRECT ANSWER:</div>
                <p className="text-sm font-mono text-foreground">
                  <span className="font-bold text-accent">{question.correct_answer}.</span> {question.options[question.correct_answer.charCodeAt(0) - 65]}
                </p>
              </div>
            )}
            
            <Button
              onClick={handleGenerateQuestion}
              data-testid="next-question-btn"
              className="w-full bg-secondary text-secondary-foreground hover:bg-secondary/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
            >
              Next Question
            </Button>
          </motion.div>
        )}
      </motion.div>
    </div>
  );
};

export default TrainingMode;
