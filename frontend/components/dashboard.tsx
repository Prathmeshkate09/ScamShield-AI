"use client";

import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock3,
  FileUp,
  ImageIcon,
  Link2,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  MessageSquareText,
  Mic,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Volume2
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { analyzeImage, analyzeText, analyzeUrl, analyzeVoice, ApiError, getHealth, getHistory, getStats } from "@/lib/api";
import { demoExamples } from "@/lib/examples";
import { createClient } from "@/lib/supabase/client";
import type { AnalysisMode, DashboardStats, RiskLevel, ScamAnalysis } from "@/types/analysis";

type SpeechRecognitionAlternative = { transcript: string };
type SpeechRecognitionResult = { [index: number]: SpeechRecognitionAlternative };
type SpeechRecognitionResults = { [index: number]: SpeechRecognitionResult };
type BrowserSpeechEvent = Event & { resultIndex: number; results: SpeechRecognitionResults };
type BrowserSpeechRecognition = {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  start: () => void;
  stop: () => void;
  onend: (() => void) | null;
  onerror: (() => void) | null;
  onresult: ((event: BrowserSpeechEvent) => void) | null;
};
type BrowserSpeechRecognitionConstructor = new () => BrowserSpeechRecognition;

declare global {
  interface Window {
    SpeechRecognition?: BrowserSpeechRecognitionConstructor;
    webkitSpeechRecognition?: BrowserSpeechRecognitionConstructor;
  }
}

type ModeCard = {
  id: AnalysisMode;
  title: string;
  caption: string;
  icon: LucideIcon;
};

const modeCards: ModeCard[] = [
  { id: "text", title: "Analyze Message", caption: "SMS, email, chat", icon: MessageSquareText },
  { id: "image", title: "Analyze Screenshot", caption: "PNG, JPG, WEBP", icon: ImageIcon },
  { id: "url", title: "Analyze URL", caption: "No risky link visits", icon: Link2 },
  { id: "voice", title: "Voice Analyzer", caption: "Browser speech input", icon: Mic }
];

const emptyStats: DashboardStats = {
  total_analyses: 0,
  high_risk_detected: 0,
  critical_scams: 0,
  most_common_scam_type: null
};

function riskClass(riskLevel: RiskLevel): string {
  return riskLevel.toLowerCase();
}

function ResultPanel({ analysis, isLoading }: { analysis: ScamAnalysis | null; isLoading: boolean }) {
  if (isLoading) {
    return (
      <section className="result-panel loading-result" aria-label="Analysis in progress">
        <div className="skeleton score-skeleton" />
        <div className="skeleton line-skeleton" />
        <div className="skeleton line-skeleton short" />
        <div className="skeleton card-skeleton" />
      </section>
    );
  }

  if (!analysis) {
    return (
      <section className="result-panel empty-result">
        <div className="empty-icon">
          <ShieldCheck size={30} />
        </div>
        <h2>Your risk assessment appears here</h2>
        <p>Choose a scan type, share the suspicious content, and ScamShield will explain the risk signals in plain language.</p>
        <div className="empty-points">
          <span><CheckCircle2 size={16} /> Explainable flags</span>
          <span><CheckCircle2 size={16} /> Clear next steps</span>
          <span><CheckCircle2 size={16} /> Private-by-design flow</span>
        </div>
      </section>
    );
  }

  return (
    <section className="result-panel">
      <div className="result-heading">
        <div>
          <p className="eyebrow">Scam risk assessment</p>
          <h2>Decision support, not a guarantee</h2>
        </div>
        <span className="timestamp"><Clock3 size={15} /> {new Date(analysis.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
      </div>

      <div className="score-grid">
        <div className={`risk-score ${riskClass(analysis.risk_level)}`}>
          <span className="score-number">{analysis.risk_score}</span>
          <span className="score-label">/100 risk score</span>
          <strong>{analysis.risk_level} RISK</strong>
        </div>
        <div className="metric-list">
          <div>
            <span>Scam type</span>
            <strong>{analysis.scam_type}</strong>
          </div>
          <div>
            <span>AI confidence</span>
            <strong>{Math.round(analysis.confidence * 100)}%</strong>
          </div>
        </div>
      </div>

      <div className="result-section">
        <h3><AlertTriangle size={18} /> Detected red flags</h3>
        {analysis.red_flags.length ? (
          <div className="flag-list">
            {analysis.red_flags.map((flag) => <span key={flag} className="flag-pill"><span>×</span>{flag}</span>)}
          </div>
        ) : (
          <p className="muted-copy">No high-confidence scam patterns were detected. Keep verifying unexpected requests independently.</p>
        )}
      </div>

      <div className="explanation-box">
        <Sparkles size={19} />
        <div>
          <h3>Why this matters</h3>
          <p>{analysis.explanation}</p>
        </div>
      </div>

      <div className="result-section action-section">
        <h3><ShieldCheck size={18} /> Recommended action</h3>
        <ul>
          {analysis.recommendation.map((recommendation) => <li key={recommendation}><ChevronRight size={16} />{recommendation}</li>)}
        </ul>
      </div>
    </section>
  );
}

export function Dashboard({ userEmail }: { userEmail: string }) {
  const [activeMode, setActiveMode] = useState<AnalysisMode>("text");
  const [message, setMessage] = useState("");
  const [url, setUrl] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [voiceTranscript, setVoiceTranscript] = useState("");
  const [analysis, setAnalysis] = useState<ScamAnalysis | null>(null);
  const [stats, setStats] = useState<DashboardStats>(emptyStats);
  const [history, setHistory] = useState<ScamAnalysis[]>([]);
  const [isDemoMode, setIsDemoMode] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [persistenceNotice, setPersistenceNotice] = useState<string | null>(null);
  const [isSigningOut, setIsSigningOut] = useState(false);

  const activeCard = modeCards.find((mode) => mode.id === activeMode) ?? modeCards[0];
  const ActiveIcon = activeCard.icon;

  const refreshDashboard = useCallback(async () => {
    const [healthResult, statsResult, historyResult] = await Promise.allSettled([getHealth(), getStats(), getHistory()]);
    if (healthResult.status === "fulfilled") {
      setIsDemoMode(healthResult.value.meta.mode === "demo");
    }
    const protectedError = [statsResult, historyResult].find((result) => result.status === "rejected");
    if (protectedError?.status === "rejected" && protectedError.reason instanceof ApiError && protectedError.reason.status === 401) {
      window.location.assign("/login?error=session");
      return;
    }
    if (statsResult.status === "fulfilled") {
      setStats(statsResult.value.data);
      setPersistenceNotice(null);
    } else {
      setPersistenceNotice("Protected history is temporarily unavailable. Please try again shortly.");
    }
    if (historyResult.status === "fulfilled") {
      setHistory(historyResult.value.data.items);
    }
  }, []);

  useEffect(() => {
    void refreshDashboard();
  }, [refreshDashboard]);

  const submitAnalysis = async () => {
    setError(null);

    try {
      setIsLoading(true);
      let response;
      if (activeMode === "text") {
        if (!message.trim()) throw new Error("Paste a suspicious message before analyzing.");
        response = await analyzeText(message.trim());
      } else if (activeMode === "url") {
        if (!url.trim()) throw new Error("Enter a complete HTTP or HTTPS URL.");
        response = await analyzeUrl(url.trim());
      } else if (activeMode === "voice") {
        if (!voiceTranscript.trim()) throw new Error("Record or paste a voice transcript before analyzing.");
        response = await analyzeVoice(voiceTranscript.trim());
      } else {
        if (!selectedFile) throw new Error("Choose a screenshot before analyzing.");
        response = await analyzeImage(selectedFile);
      }
      setAnalysis(response.data);
      setIsDemoMode(response.meta.mode === "demo");
      if (!response.meta.persisted) {
        setPersistenceNotice("Demo result generated. Add DATABASE_URL to persist this scan.");
      }
      await refreshDashboard();
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.status === 401) {
        window.location.assign("/login?error=session");
        return;
      }
      setError(requestError instanceof Error ? requestError.message : "The analysis could not be completed.");
    } finally {
      setIsLoading(false);
    }
  };

  const signOut = async () => {
    setIsSigningOut(true);
    try {
      const { error: signOutError } = await createClient().auth.signOut({ scope: "global" });
      if (signOutError) {
        setError("Sign out did not complete. Try again before leaving this device unattended.");
        return;
      }
      window.location.assign("/login");
    } finally {
      setIsSigningOut(false);
    }
  };

  const startVoiceCapture = () => {
    const SpeechRecognition = window.SpeechRecognition ?? window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      setError("Speech recognition is not available in this browser. Paste a transcript to continue.");
      return;
    }
    setError(null);
    const recognition = new SpeechRecognition();
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = "en-IN";
    recognition.onresult = (event) => {
      setVoiceTranscript(event.results[event.resultIndex][0]?.transcript ?? "");
    };
    recognition.onerror = () => {
      setError("Voice capture did not complete. Check microphone permission or paste the transcript.");
      setIsListening(false);
    };
    recognition.onend = () => setIsListening(false);
    setIsListening(true);
    recognition.start();
  };

  const useExample = (exampleValue: string) => {
    setActiveMode("text");
    setMessage(exampleValue);
    setError(null);
  };

  return (
    <main className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <header className="topbar">
        <a className="brand" href="#" aria-label="ScamShield AI home">
          <span className="brand-mark"><ShieldCheck size={24} /></span>
          <span>ScamShield <strong>AI</strong></span>
        </a>
        <div className="account-controls">
          <div className="topbar-status">
            <span className={`status-dot ${isDemoMode ? "demo" : "live"}`} />
            {isDemoMode ? "Demo protection mode" : "Live AI protection"}
          </div>
          <span className="account-email" title={userEmail}>{userEmail}</span>
          <button className="logout-button" disabled={isSigningOut} onClick={() => void signOut()} type="button">
            <LogOut size={15} /> {isSigningOut ? "Signing out" : "Sign out"}
          </button>
        </div>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow"><Activity size={15} /> AI-powered threat intelligence</p>
          <h1>Detect the scam <span>before</span> you take the bait.</h1>
          <p>Analyze suspicious messages, screenshots, URLs, and voice transcripts with explainable risk signals designed for fast, safer decisions.</p>
        </div>
        <div className="security-promise">
          <LockKeyhole size={20} />
          <span>We never open submitted URLs.<br />Your scan stays in your control.</span>
        </div>
      </section>

      {isDemoMode && (
        <section className="demo-banner">
          <Sparkles size={18} />
          <span><strong>Demo mode is active.</strong> Deterministic showcase analysis is running until an OpenAI or Gemini key is configured.</span>
        </section>
      )}

      <section className="stats-grid" aria-label="ScamShield statistics">
        <article><span>Total scans</span><strong>{stats.total_analyses}</strong><small>Persistent analyses</small></article>
        <article><span>High risk detected</span><strong>{stats.high_risk_detected}</strong><small>High + critical results</small></article>
        <article><span>Critical scams</span><strong>{stats.critical_scams}</strong><small>Immediate caution advised</small></article>
        <article><span>Top pattern</span><strong className="type-stat">{stats.most_common_scam_type ?? "—"}</strong><small>Across saved analyses</small></article>
      </section>

      <section className="workspace">
        <div className="scan-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">Start a scan</p>
              <h2>What needs checking?</h2>
            </div>
            <span className="secure-label"><LockKeyhole size={14} /> Security-first</span>
          </div>

          <div className="mode-grid">
            {modeCards.map((mode) => {
              const Icon = mode.icon;
              return (
                <button
                  className={`mode-card ${activeMode === mode.id ? "selected" : ""}`}
                  key={mode.id}
                  onClick={() => { setActiveMode(mode.id); setError(null); }}
                  type="button"
                >
                  <Icon size={20} />
                  <span>{mode.title}</span>
                  <small>{mode.caption}</small>
                </button>
              );
            })}
          </div>

          <div className="input-zone">
            <div className="input-zone-heading">
              <div>
                <p className="eyebrow">{activeCard.title}</p>
                <h3>{activeMode === "text" ? "Paste the message exactly as received" : activeMode === "image" ? "Upload the suspicious screenshot" : activeMode === "url" ? "Inspect a URL without visiting it" : "Capture or paste the call transcript"}</h3>
              </div>
              <ActiveIcon size={24} />
            </div>

            {activeMode === "text" && (
              <textarea
                aria-label="Suspicious message"
                maxLength={10000}
                onChange={(event) => setMessage(event.target.value)}
                placeholder="Paste a suspicious message here..."
                value={message}
              />
            )}

            {activeMode === "url" && (
              <div className="url-input-wrap">
                <Link2 size={20} />
                <input aria-label="Suspicious URL" onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/account/verify" type="url" value={url} />
              </div>
            )}

            {activeMode === "image" && (
              <label className={`upload-zone ${selectedFile ? "has-file" : ""}`}>
                <input accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp" onChange={(event) => setSelectedFile(event.target.files?.[0] ?? null)} type="file" />
                <FileUp size={26} />
                <strong>{selectedFile ? selectedFile.name : "Choose a screenshot"}</strong>
                <span>{selectedFile ? "Ready for secure analysis" : "PNG, JPG, JPEG, or WEBP · max 10 MB"}</span>
              </label>
            )}

            {activeMode === "voice" && (
              <div className="voice-zone">
                <button className={`voice-button ${isListening ? "listening" : ""}`} onClick={startVoiceCapture} type="button">
                  {isListening ? <LoaderCircle className="spin" size={23} /> : <Volume2 size={23} />}
                  {isListening ? "Listening..." : "Start analysis"}
                </button>
                <textarea
                  aria-label="Voice transcript"
                  maxLength={10000}
                  onChange={(event) => setVoiceTranscript(event.target.value)}
                  placeholder="Your transcript will appear here, or paste the caller's words..."
                  value={voiceTranscript}
                />
              </div>
            )}

            {error && <p className="error-message"><AlertTriangle size={16} /> {error}</p>}

            <button className="primary-button analyze-button" disabled={isLoading} onClick={() => void submitAnalysis()} type="button">
              {isLoading ? <LoaderCircle className="spin" size={18} /> : <Send size={18} />}
              {isLoading ? "Analyzing signals..." : activeMode === "image" ? "Analyze Screenshot" : activeMode === "voice" ? "Analyze Voice" : activeMode === "url" ? "Analyze URL" : "Analyze Message"}
            </button>
          </div>

          <div className="examples">
            <div><p className="eyebrow">Judge-ready examples</p><span>One click to populate</span></div>
            <div className="example-list">
              {demoExamples.map((example) => (
                <button key={example.label} onClick={() => useExample(example.value)} type="button">
                  <strong>{example.label}</strong>
                  <span>{example.description}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <ResultPanel analysis={analysis} isLoading={isLoading} />
      </section>

      <section className="history-section">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Analysis history</p>
            <h2>Recent protection decisions</h2>
          </div>
          {persistenceNotice && <p className="persistence-notice"><LockKeyhole size={15} /> {persistenceNotice}</p>}
        </div>
        {history.length ? (
          <div className="history-list">
            {history.map((item) => (
              <button className="history-row" key={item.id} onClick={() => setAnalysis(item)} type="button">
                <span className={`history-score ${riskClass(item.risk_level)}`}>{item.risk_score}</span>
                <span className="history-main"><strong>{item.scam_type}</strong><small>{item.input_type} analysis · {new Date(item.created_at).toLocaleDateString()}</small></span>
                <span className={`risk-badge ${riskClass(item.risk_level)}`}>{item.risk_level}</span>
                <ChevronRight size={18} />
              </button>
            ))}
          </div>
        ) : (
          <div className="history-empty"><Clock3 size={20} /> Your saved scans will appear here once PostgreSQL is connected.</div>
        )}
      </section>

      <footer>
        <span><ShieldAlert size={16} /> ScamShield AI is a security assistant, not a replacement for official support or emergency reporting.</span>
        <span>Detect the scam before you take the bait.</span>
      </footer>
    </main>
  );
}
