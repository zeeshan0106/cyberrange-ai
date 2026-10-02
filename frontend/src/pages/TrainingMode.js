import { useState, useEffect } from "react";
import axios from "axios";
import { motion } from "framer-motion";
import { 
  GraduationCap, 
  CheckCircle, 
  XCircle, 
  AlertCircle,
  Loader2, 
  Flame, 
  Target, 
  CheckCheck,
  FastForward,
  Sparkles,
  HelpCircle
} from "lucide-react";
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
  const [submitting, setSubmitting] = useState(false);
  const [stats, setStats] = useState({
    total_score: 0,
    questions_answered: 0,
    overall_accuracy: 0.0,
    current_streak: 0
  });

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/training/stats`);
      if (response.data) {
        setStats(response.data);
      }
    } catch (error) {
      console.error("Failed to load training stats:", error);
    }
  };

  const cleanText = (txt) => {
    if (typeof txt !== "string") return "";
    let clean = txt.replace(/<[^>]+>/g, "");
    clean = clean.replace(/^[\*\-\•\s]+/, "").trim();
    return clean;
  };

  const cleanOption = (txt) => {
    if (typeof txt !== "string") return "";
    let clean = cleanText(txt);
    clean = clean.replace(/^(?:[oO]ption\s*)?\(?[a-dA-D1-4]\)?[\.\:\)\-\]\s]+\s*/, "").trim();
    return clean;
  };

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
    if (!selectedAnswer || submitting || !question) {
      toast.error("Please select an answer first");
      return;
    }

    setSubmitting(true);
    try {
      const response = await axios.post(`${API}/training/answer`, {
        question_id: question.id,
        user_answer: selectedAnswer,
        skipped: false
      });
      setResult(response.data);
      if (response.data.total_score !== undefined) {
        setStats({
          total_score: response.data.total_score,
          questions_answered: (stats.questions_answered || 0) + 1,
          overall_accuracy: response.data.accuracy ?? stats.overall_accuracy,
          current_streak: response.data.streak ?? stats.current_streak
        });
      }
      if (response.data.correct) {
        toast.success(`Correct! +${response.data.score_gained} points`);
      } else {
        toast.error("Incorrect answer");
      }
    } catch (error) {
      console.error(error);
      toast.error("Failed to submit answer");
    } finally {
      setSubmitting(false);
    }
  };

  const handleSkipQuestion = async () => {
    if (submitting || !question) return;

    setSubmitting(true);
    try {
      const response = await axios.post(`${API}/training/answer`, {
        question_id: question.id,
        skipped: true
      });
      setResult(response.data);
      if (response.data.total_score !== undefined) {
        setStats({
          total_score: response.data.total_score,
          questions_answered: (stats.questions_answered || 0) + 1,
          overall_accuracy: response.data.accuracy ?? stats.overall_accuracy,
          current_streak: response.data.streak ?? stats.current_streak
        });
      }
      toast.info("Question skipped");
    } catch (error) {
      console.error(error);
      toast.error("Failed to skip question");
    } finally {
      setSubmitting(false);
    }
  };

  // Whether a question is active and awaiting an answer
  const isQuestionPending = Boolean(question && !result);

  return (
    <div className="py-8" data-testid="training-mode-page">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        {/* Header & Unified Stats Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-3">
            <GraduationCap className="w-8 h-8 text-secondary" />
            <div>
              <h1 className="text-4xl font-rajdhani font-bold uppercase tracking-wider text-secondary">
                Training Mode
              </h1>
              <p className="text-xs font-mono text-muted-foreground mt-0.5">
                Targeted interactive quiz modules with PICERL and ATT&CK alignment
              </p>
            </div>
          </div>

          {/* Unified Score Bar */}
          <div className="grid grid-cols-4 gap-3 bg-black/50 border border-white/10 rounded-sm p-3 font-mono text-center">
            <div className="px-3 py-1 border-r border-white/10" data-testid="score-display">
              <div className="text-[10px] text-muted-foreground uppercase">Total Score</div>
              <div className="text-xl font-rajdhani font-bold text-secondary">{stats.total_score}</div>
            </div>
            <div className="px-3 py-1 border-r border-white/10">
              <div className="text-[10px] text-muted-foreground uppercase flex items-center justify-center gap-1">
                <CheckCheck className="w-3 h-3 text-primary" /> Questions
              </div>
              <div className="text-xl font-rajdhani font-bold text-foreground">{stats.questions_answered}</div>
            </div>
            <div className="px-3 py-1 border-r border-white/10">
              <div className="text-[10px] text-muted-foreground uppercase flex items-center justify-center gap-1">
                <Target className="w-3 h-3 text-accent" /> Accuracy
              </div>
              <div className="text-xl font-rajdhani font-bold text-accent">{stats.overall_accuracy}%</div>
            </div>
            <div className="px-3 py-1">
              <div className="text-[10px] text-muted-foreground uppercase flex items-center justify-center gap-1">
                <Flame className="w-3 h-3 text-destructive" /> Streak
              </div>
              <div className="text-xl font-rajdhani font-bold text-destructive">{stats.current_streak}</div>
            </div>
          </div>
        </div>

        {/* Configuration Bar */}
        <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 mb-6">
          <div className="flex flex-col sm:flex-row sm:items-end gap-4">
            <div className="flex-1">
              <Label htmlFor="scenario" className="text-sm font-mono text-muted-foreground mb-2 block">
                Question Category
              </Label>
              <Select
                value={scenarioType}
                onValueChange={setScenarioType}
                disabled={isQuestionPending}
              >
                <SelectTrigger id="scenario" data-testid="select-scenario-type" className="bg-black/50 border-white/20 font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-black border-white/20 font-mono">
                  <SelectItem value="Phishing">Phishing Awareness</SelectItem>
                  <SelectItem value="Ransomware">Ransomware Defense</SelectItem>
                  <SelectItem value="General Security">General Security Principles</SelectItem>
                  <SelectItem value="Incident Response">Incident Response (PICERL)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Button
              onClick={handleGenerateQuestion}
              disabled={loading || isQuestionPending}
              data-testid="generate-question-btn"
              className="bg-secondary text-secondary-foreground hover:bg-secondary/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                "New Question"
              )}
            </Button>
          </div>
          {isQuestionPending && (
            <p className="text-xs font-mono text-amber-400/80 mt-2.5">
              Submit an answer or click Skip to finish the active question before requesting a new one.
            </p>
          )}
        </div>

        {/* Question Panel */}
        {question && (
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-6 mb-6" data-testid="question-section">
            <div className="flex items-center justify-between gap-2 mb-4 pb-3 border-b border-white/10">
              <span className="text-xs font-mono text-secondary px-2.5 py-1 rounded-sm bg-secondary/10 border border-secondary/30 uppercase font-bold">
                Category: {question.category || scenarioType}
              </span>
              {question.generation_source && (
                <span className="text-[11px] font-mono text-muted-foreground">
                  Source: {question.generation_source === "llm" ? "AI Model" : "Curated Bank"}
                </span>
              )}
            </div>

            <h2 className="text-lg md:text-xl font-rajdhani font-bold mb-6 text-foreground leading-relaxed">
              {cleanText(question.question)}
            </h2>

            <RadioGroup 
              value={selectedAnswer} 
              onValueChange={setSelectedAnswer}
              disabled={submitting || Boolean(result)}
            >
              <div className="space-y-3">
                {question.options.map((option, index) => {
                  const letter = String.fromCharCode(65 + index);
                  const isSelected = selectedAnswer === letter;
                  const isCorrect = result && question.correct_answer === letter;
                  const isWrongSelection = result && !result.correct && isSelected;

                  let borderStyle = "bg-black/60 border-white/20 hover:border-white/40";
                  if (result) {
                    if (isCorrect) {
                      borderStyle = "bg-emerald-500/10 border-emerald-500 text-emerald-400";
                    } else if (isWrongSelection) {
                      borderStyle = "bg-destructive/10 border-destructive text-destructive";
                    } else {
                      borderStyle = "bg-black/40 border-white/10 opacity-60";
                    }
                  } else if (isSelected) {
                    borderStyle = "bg-primary/15 border-primary text-primary-foreground";
                  }

                  return (
                    <div
                      key={index}
                      className={`flex items-start space-x-3 p-4 rounded-sm border transition-all ${borderStyle}`}
                    >
                      <RadioGroupItem
                        value={letter}
                        id={`option-${letter}`}
                        data-testid={`option-${letter}`}
                        disabled={submitting || Boolean(result)}
                        className="mt-0.5 border-white/40"
                      />
                      <Label
                        htmlFor={`option-${letter}`}
                        className="flex-1 cursor-pointer font-mono text-sm leading-relaxed"
                      >
                        <span className="font-bold mr-2 text-primary">{letter}.</span>
                        <span>{cleanOption(option)}</span>
                      </Label>
                    </div>
                  );
                })}
              </div>
            </RadioGroup>

            {/* Actions Bar: Submit and Skip */}
            {!result && (
              <div className="flex flex-col sm:flex-row items-center gap-3 mt-6">
                <Button
                  onClick={handleSubmitAnswer}
                  disabled={submitting || !selectedAnswer}
                  data-testid="submit-answer-btn"
                  className="w-full sm:flex-1 bg-accent text-accent-foreground hover:bg-accent/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest"
                >
                  {submitting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Evaluating...
                    </>
                  ) : (
                    "Submit Answer"
                  )}
                </Button>

                <Button
                  onClick={handleSkipQuestion}
                  disabled={submitting}
                  variant="outline"
                  data-testid="skip-question-btn"
                  className="w-full sm:w-auto border-white/20 text-muted-foreground hover:text-foreground hover:bg-white/5 font-mono uppercase text-xs tracking-wider"
                >
                  <FastForward className="w-3.5 h-3.5 mr-1.5" />
                  Skip Question
                </Button>
              </div>
            )}
          </div>
        )}

        {/* ONE Unified Feedback Panel */}
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`bg-black/50 backdrop-blur-md border rounded-sm p-6 space-y-5 shadow-2xl ${
              result.skipped
                ? "border-amber-500/40"
                : result.correct
                ? "border-emerald-500/50"
                : "border-destructive/50"
            }`}
            data-testid="result-section"
          >
            {/* Status Header */}
            <div className="flex items-center justify-between border-b border-white/10 pb-4">
              <div className="flex items-center gap-3">
                {result.skipped ? (
                  <>
                    <AlertCircle className="w-6 h-6 text-amber-400" />
                    <div>
                      <h3 className="text-xl font-rajdhani font-bold uppercase text-amber-400">
                        Question Skipped
                      </h3>
                      <span className="text-xs font-mono text-muted-foreground">0 points recorded</span>
                    </div>
                  </>
                ) : result.correct ? (
                  <>
                    <CheckCircle className="w-6 h-6 text-emerald-400" />
                    <div>
                      <h3 className="text-xl font-rajdhani font-bold uppercase text-emerald-400">
                        Correct Answer!
                      </h3>
                      <span className="text-xs font-mono text-emerald-400/80">+{result.score_gained} points gained</span>
                    </div>
                  </>
                ) : (
                  <>
                    <XCircle className="w-6 h-6 text-destructive" />
                    <div>
                      <h3 className="text-xl font-rajdhani font-bold uppercase text-destructive">
                        Incorrect Answer
                      </h3>
                      <span className="text-xs font-mono text-muted-foreground">0 points gained</span>
                    </div>
                  </>
                )}
              </div>

              {question && (
                <div className="text-right font-mono text-xs">
                  <span className="text-muted-foreground block text-[10px] uppercase">Correct Option:</span>
                  <span className="text-emerald-400 font-bold text-sm">
                    Option {result.correct_answer || question.correct_answer}
                  </span>
                </div>
              )}
            </div>

            {/* Primary Technical Explanation */}
            <div className="bg-black/60 border border-white/10 rounded-sm p-4 space-y-1.5">
              <div className="text-xs font-mono text-secondary uppercase font-bold flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5" /> Technical Explanation:
              </div>
              <p className="text-sm font-mono text-foreground/90 leading-relaxed">
                {cleanText(result.explanation)}
              </p>
            </div>

            {/* Option Breakdown Section */}
            {question && (
              <div className="space-y-2.5 pt-2">
                <div className="text-xs font-mono text-muted-foreground uppercase font-bold flex items-center gap-1">
                  <HelpCircle className="w-3.5 h-3.5 text-primary" /> Option Analysis Breakdown:
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {question.options.map((opt, idx) => {
                    const letter = String.fromCharCode(65 + idx);
                    const isCorrectLetter = (result.correct_answer || question.correct_answer) === letter;
                    const optExpl = result.option_explanations?.[letter] || question.option_explanations?.[letter];

                    return (
                      <div
                        key={idx}
                        className={`p-3 rounded-sm border font-mono text-xs space-y-1 ${
                          isCorrectLetter
                            ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-300"
                            : "bg-white/[0.02] border-white/10 text-muted-foreground"
                        }`}
                      >
                        <div className="flex items-center justify-between font-bold">
                          <span className={isCorrectLetter ? "text-emerald-400" : "text-foreground"}>
                            {letter}. {cleanOption(opt)}
                          </span>
                          <span className={`text-[10px] px-1.5 py-0.2 rounded uppercase ${
                            isCorrectLetter ? "bg-emerald-500/20 text-emerald-400" : "bg-white/10 text-muted-foreground"
                          }`}>
                            {isCorrectLetter ? "Correct" : "Distractor"}
                          </span>
                        </div>
                        {optExpl && (
                          <p className="text-[11px] leading-relaxed text-muted-foreground/90 pt-0.5">
                            {cleanText(optExpl)}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Proceed to Next Question Button */}
            <Button
              onClick={handleGenerateQuestion}
              data-testid="next-question-btn"
              className="w-full bg-secondary text-secondary-foreground hover:bg-secondary/90 rounded-sm font-rajdhani font-bold uppercase tracking-widest pt-2.5 pb-2.5"
            >
              Next Question
            </Button>
          </motion.div>
        )}

        {/* Initial Empty State */}
        {!question && !loading && (
          <div className="bg-black/40 backdrop-blur-md border border-white/10 rounded-sm p-12 text-center text-muted-foreground space-y-3">
            <GraduationCap className="w-16 h-16 opacity-30 text-secondary mx-auto" />
            <h3 className="font-rajdhani font-bold text-lg uppercase text-foreground">Ready for Training</h3>
            <p className="font-mono text-xs max-w-md mx-auto">
              Select a question category above and click <strong>New Question</strong> to begin testing your defensive cybersecurity knowledge.
            </p>
          </div>
        )}
      </motion.div>
    </div>
  );
};

export default TrainingMode;
