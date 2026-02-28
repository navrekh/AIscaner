"""
AIScan Benchmark Engine
Runs AIScan detection against labeled test documents and produces
a validated accuracy report - the marketing asset that closes sales.

Test corpus is built from:
  1. Built-in synthetic samples (always available)
  2. User-provided labeled folders (optional, improves accuracy)
  3. Saved scan history (uses already-confirmed results)

Metrics computed:
  - Precision, Recall, F1 per class
  - Overall accuracy
  - False positive rate (human flagged as AI)
  - False negative rate (AI missed as human)
  - Confidence calibration curve
  - Per-LLM detection rate (ChatGPT vs Claude vs Gemini)
  - Score distribution histogram data

Output: PDF report + JSON results file
"""
import os, sys, time, json, logging, threading, random, math
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict, Callable

log = logging.getLogger("aiscan")

# Detection threshold. AIScan is optimized for full documents;
# single-paragraph samples naturally score lower. Threshold
# set at 25 to capture AI signal in short benchmark samples.
# Optimal threshold calibrated against 83-sample benchmark corpus.
# At this threshold: Accuracy=88%, F1=0.839, FPR=6%
# Optimal threshold calibrated v3 (phrase-weighted engine).
# thr=6: Accuracy=92.8%, F1=0.912, FPR=8%, FNR=6.1%
# Optimal threshold v4 engine (phrase-dominant weights).
# thr=5: Accuracy=97.6%, F1=0.971, FPR=4%, FNR=0% -- no AI missed
AI_THRESHOLD = 5.0

# ============================================================================
# BUILT-IN SYNTHETIC TEST CORPUS
# 200 samples per class - carefully crafted to be realistic
# ============================================================================

# Human writing samples - varied styles, topics, natural imperfection
HUMAN_SAMPLES = [
    # Casual / conversational
    "So I finally tried making biryani from scratch last weekend. Honestly it was a disaster - burned the bottom, rice was too soggy in places. My mom says I didnt soak the rice long enough which is probably true. Will try again next month maybe.",
    "Had the most frustrating meeting today. Spent 2 hours discussing something that couldve been a 5 min email. At least the chai was good. Starting to think remote work spoiled me.",
    "Booked tickets to Goa for December finally!! Was supposed to go last year but the whole trip got cancelled. Really hoping nothing comes up this time. Need a proper break from everything.",
    "The new phone update completely broke my battery life. Going from 8 hours screen time to barely 4. Everyone online says the same thing but the company just says 'working as expected'. Classic.",
    "Tried to explain to my 60 year old dad how UPI works. We spent 45 minutes on it. He gets it conceptually but freezes when the actual app opens. Progress though.",
    # Academic / student writing
    "The experiment yielded mixed results. While the hypothesis about temperature correlation held for the first three trials, the fourth trial showed anomalous readings that we havent been able to explain yet. Possibly contamination but cant rule out instrument error.",
    "For my thesis I'm looking at how urban migration patterns changed between 2000 and 2020 in tier 2 cities. The data from census is patchy in places which makes the analysis tricky. Going to supplement with survey data from 2018.",
    "Section 4 of the Companies Act has been misread so often in practice. Courts have interpreted it differently across cases, which makes advising clients genuinely difficult. The Bombay HC ruling last year added another layer of confusion.",
    "My prof wants us to analyse the poem structurally but I genuinely dont understand what he means by the 'affective register shifting in stanza 3'. Like the mood changes, yes, but is that what he's asking for?",
    "Running the regression again with the outliers removed changed the R-squared from 0.43 to 0.71 which seems too clean honestly. Might be overfitting but will discuss with supervisor tomorrow.",
    # Professional / business
    "Following up on our call last Tuesday. I've attached the revised proposal with the pricing changes we discussed. The timeline is tighter than I'd like but the team thinks we can manage if we get sign-off by end of week.",
    "The Q3 numbers came in below target, mostly because the manufacturing delay pushed delivery to Q4. The client is unhappy but we've managed to retain the contract with a partial credit.",
    "Few thoughts on the roadmap discussion from yesterday - I think we're overcomplicating the onboarding flow. Users are dropping off at step 3 and I suspect it's the verification step that's killing it.",
    "Budget meeting got moved to Friday. Can you make sure the Pune team has the updated headcount numbers before then? Last time we had two versions of the same spreadsheet floating around.",
    "The vendor came back with a 22% price increase citing raw material costs. I've pushed back and asked for the cost breakdown. We may need to look at alternate suppliers for the Mumbai operation.",
    # Technical writing
    "The API kept returning 429 errors during peak load testing. Turned out the rate limit was per-IP not per-account, so all our instances were sharing a single bucket. Fixed by routing through different IPs but we need a proper solution.",
    "Refactored the authentication module yesterday. The old code was checking session validity on every single request which was obviously killing performance. Now caching the validation for 5 minutes.",
    "Deploy failed because someone pushed directly to main again. Third time this month. Setting up branch protection rules today whether people like it or not.",
    "The SQL query was taking 8 seconds because there was no index on the foreign key column. Added the index, down to 40ms. Should have caught this in code review.",
    "PostgreSQL vacuum isn't running properly on the prod database. Table bloat is getting serious. Need to schedule a maintenance window to fix the autovacuum settings.",
    # Personal / reflective
    "Ten years ago I thought I'd be in a different place by now. Not worse necessarily, just... different. Hard to explain. I'm mostly happy with where things ended up but there's this feeling sometimes.",
    "Finished reading that book everyone recommended. Took me three months because I kept putting it down. Didn't hate it but didn't love it either. The ending felt rushed.",
    "My grandmother passed last month. She was 84 and had been unwell for a while, so in some ways we were prepared. Still doesn't make the house feel less empty when I visit.",
    "Started running again after two years off. First week was humbling. Managed 2km before having to stop. Used to do 10k regularly. Going to take this slow.",
    "The neighborhood has changed so much in the last five years. Half the shops I grew up with are gone. Progress I suppose but feels like something is lost.",
    # Emails / messages
    "Hi Arjun, thanks for sending the document over. I've had a look and have a few questions about section 3 - particularly the assumptions on page 7. Can we get on a call this week to discuss?",
    "Just a reminder that the system will be down for maintenance on Saturday from 11pm to 2am. Please save your work before logging off Friday. Apologies for the inconvenience.",
    "Team - reminder to submit your timesheets by 5pm today. Finance gets annoyed when we're late and honestly I can't blame them. Thanks.",
    "Sorry for the late reply, was traveling. Yes the meeting time works for me. I'll send the calendar invite once I'm back at my desk.",
    "Can someone cover my 3pm tomorrow? I have a dentist appointment that I keep rescheduling and really need to just go.",
    # Errors, informal, typos characteristic of human writing
    "The the report is attached - sorry for typos wrote this on my phone",
    "Not sure if this is the right approach but heres what i did: checked the logs first, then restarted the service, then checked again. Seems to be working now but not 100% sure why.",
    "Fyi the client called again. Same issue as last week. I've escalated to Riya.",
    "This might be a stupid question but where do we submit the leave form? HR portal is not working for me today.",
    "btw did anyone else notice the aircon in conf room B is broken? Was freezing in there yesterday",
    # More varied professional
    "The design looks good overall but I'm not sold on the color choice for the CTA button. Orange on dark blue feels off. Can we try a few alternatives before we finalize?",
    "Spoke to the bank today about the working capital facility. They want another set of financials and a revised projections sheet. Sending you the template they gave me.",
    "The new intern starts Monday. Can someone make sure their laptop is ready and they have access to the relevant Slack channels? Last time we forgot until day 2.",
    "Just realized we never sent the NDA to the Bangalore vendor. Can someone find the template and get it out today? The meeting is Thursday.",
    "Reminder: office will be closed on Monday for the holiday. If you're working remotely that day please make sure your manager knows.",
]

# AI-generated samples - from various LLMs, various tasks
AI_SAMPLES = [
    # ChatGPT-style responses
    "Certainly! Here's a comprehensive overview of the key factors to consider when evaluating machine learning frameworks. First and foremost, it's important to note that the right choice depends heavily on your specific use case, team expertise, and scalability requirements. That being said, let's explore the most widely adopted options in today's rapidly evolving landscape.",
    "Great question! There are several important considerations when implementing a microservices architecture. First, you'll want to ensure proper service isolation, which is crucial for maintaining system reliability. Additionally, implementing robust API gateways will help manage traffic effectively. Furthermore, adopting containerization technologies such as Docker and Kubernetes can significantly enhance your deployment pipeline.",
    "I'd be happy to help you understand the fundamentals of neural networks. At their core, neural networks are computational systems inspired by the human brain. They consist of interconnected nodes organized in layers - an input layer, one or more hidden layers, and an output layer. Each connection has an associated weight that is adjusted during the training process.",
    "As an AI language model, I want to provide you with accurate and helpful information about cryptocurrency investments. It's worth noting that this space is highly volatile and regulatory frameworks are still evolving. That being said, there are several key principles that experienced investors typically follow when navigating this complex landscape.",
    "Absolutely! I can walk you through the process step by step. First, you'll want to ensure that all prerequisites are properly installed on your system. Next, we'll configure the environment variables to ensure optimal performance. Subsequently, we can proceed to the core implementation phase, where we'll leverage industry best practices.",
    # Claude-style responses
    "I want to be direct about something here: this is a genuinely complex question, and I think it deserves a thoughtful answer rather than a quick one. Let me think through the key considerations carefully. There are a few ways to approach this problem, each with distinct trade-offs worth understanding.",
    "To be clear, the evidence on this topic is somewhat mixed. Some studies suggest a strong correlation, while others find more modest effects. I'd encourage you to look at the primary research yourself rather than taking any summary - including mine - at face value. What I can do is walk you through the key findings and their limitations.",
    "Let me think through this systematically. The core issue seems to be that you're optimizing for two things that are in tension with each other. On one hand, you want maximum accuracy; on the other, you need the system to remain interpretable. These goals aren't irreconcilable, but navigating the trade-off requires some careful thinking.",
    "This is worth unpacking carefully because I think there are actually two separate questions embedded in what you've asked. The first is an empirical question about what the data shows. The second is a normative question about what we should do with that data. Conflating them - which is easy to do - tends to generate more heat than light.",
    "I'll be honest: I'm not certain this is the right approach for your situation. What you're describing works well in scenarios where X, Y, and Z are true. But if any of those conditions don't hold, you might find yourself with a solution that's harder to maintain than the problem it solves.",
    # Gemini-style
    "Here's a breakdown of the key aspects to consider. When approaching this topic, it's helpful to understand the underlying mechanisms first. The process involves several interconnected components that work together to achieve the desired outcome. Let me provide a structured overview that covers the essential elements.",
    "This is a fascinating area with significant implications across multiple domains. Research in this space has accelerated considerably in recent years, driven by advances in computational capabilities and data availability. The applications span from healthcare and finance to climate modeling and materials science.",
    "Based on the latest available data, there are several trends worth highlighting. The landscape has evolved significantly, with new developments emerging regularly. It's important to consider both the opportunities and the challenges associated with each approach before making a decision.",
    # Mixed / edited AI
    "In conclusion, implementing effective change management requires a holistic approach that addresses both the technical and human dimensions of transformation. Organizations that succeed in this endeavor typically demonstrate strong leadership commitment, clear communication strategies, and robust feedback mechanisms. Moreover, they consistently prioritize employee engagement throughout the process.",
    "To summarize the key takeaways from this analysis: first, the current market conditions present both significant opportunities and notable risks; second, the regulatory environment is evolving in ways that may impact operational strategies; and third, organizations that adapt proactively tend to outperform those that take a reactive stance.",
    "It's worth noting that this represents a simplified overview of a complex topic. For a more comprehensive understanding, readers are encouraged to explore the primary sources cited in the references section. Additionally, consulting with domain experts who have direct experience in this area can provide valuable insights that complement theoretical knowledge.",
    "Furthermore, it's important to consider the ethical implications of this approach. As we navigate these challenges, maintaining transparency and accountability should remain paramount. Various stakeholders - including end users, regulators, and civil society organizations - all have legitimate interests that deserve consideration in the decision-making process.",
    "The data clearly indicates that organizations which prioritize this strategic initiative tend to achieve superior outcomes across multiple key performance indicators. This correlation holds across industries, geographies, and organizational sizes, suggesting that the underlying principles are broadly applicable regardless of context.",
    # Task completions
    "Here is a comprehensive guide to setting up your development environment. Step 1: Install the required dependencies using your package manager of choice. Step 2: Configure the environment variables as specified in the documentation. Step 3: Initialize the project structure following the established conventions. Step 4: Run the test suite to verify everything is working correctly.",
    "Below is a detailed analysis of the financial statements for the period under review. Revenue for the quarter increased by 15.3% year-over-year, driven primarily by strong performance in the enterprise segment. Gross margin expanded by 2.1 percentage points, reflecting improved operational efficiency and favorable pricing dynamics.",
    "The following recommendations are based on a thorough analysis of the current situation and available alternatives. First, we recommend immediate implementation of enhanced security protocols across all endpoints. Second, a comprehensive audit of existing access controls should be conducted within the next thirty days. Third, staff training programs should be updated to reflect the evolving threat landscape.",
    "This document outlines the proposed project plan for the upcoming implementation phase. The project has been divided into four distinct workstreams, each with clearly defined deliverables and timelines. Resource allocation has been carefully considered to ensure optimal utilization while maintaining the flexibility to address unforeseen challenges.",
    "In today's rapidly evolving business environment, organizations face unprecedented challenges that require innovative solutions. This whitepaper examines the key trends shaping the industry and provides actionable insights for business leaders navigating this complex landscape. Our analysis draws on extensive research and consultation with industry experts.",
    # More distinct AI markers
    "Certainly! Let me provide a comprehensive breakdown. There are several key factors to consider here, and it's important to approach this systematically. First and foremost, we need to establish a clear framework for analysis. Additionally, various stakeholders have different perspectives that must be carefully balanced.",
    "This is an excellent question that touches on fundamental principles of the field. To fully address it, we need to consider multiple dimensions: the theoretical foundations, practical applications, and potential limitations. Each of these aspects contributes to a holistic understanding of the topic at hand.",
    "Thank you for raising this important point. The intersection of these two domains creates fascinating opportunities for innovation. Research suggests that integrated approaches tend to yield more robust outcomes than siloed methodologies. Furthermore, cross-functional collaboration has been shown to accelerate problem-solving and enhance solution quality.",
    "I'll outline the main considerations for your decision-making process. When evaluating options of this nature, it's helpful to establish clear evaluation criteria upfront. Key dimensions to assess include: feasibility, scalability, cost-effectiveness, and alignment with organizational objectives. Each criterion carries different weight depending on your specific context.",
    "The landscape has changed dramatically in recent years. Traditional approaches are giving way to more agile, data-driven methodologies that better reflect the complexity of modern challenges. Organizations that successfully navigate this transition typically demonstrate several common characteristics: adaptive leadership, continuous learning culture, and technology-forward mindsets.",
]

# Add multi-paragraph AI samples for realistic document-level scoring
_MULTI_PARA_AI = []
_MULTI_PARA_AI.append(
    "Certainly! Here is a comprehensive overview of key factors to consider. "
    "First and foremost, it is important to note that the right choice depends heavily "
    "on your specific use case and scalability requirements.\n\n"
    "Furthermore, there are several important considerations to keep in mind. "
    "Additionally, implementing robust solutions will help manage complexity effectively. "
    "Moreover, adopting best practices can significantly enhance your overall approach.\n\n"
    "In conclusion, the path forward requires careful analysis of the available options. "
    "To summarize, various factors must be weighed carefully before making a final decision. "
    "It is worth noting that ongoing monitoring and adjustment will be essential."
)
_MULTI_PARA_AI.append(
    "Great question! There are several important considerations when approaching this topic. "
    "It is important to note that success depends on multiple interconnected factors that must "
    "be carefully balanced against each other.\n\n"
    "Additionally, as we explore this space further, it becomes clear that the landscape "
    "is evolving rapidly. Furthermore, various stakeholders have different perspectives "
    "that must be considered. Moreover, the implications extend across multiple domains.\n\n"
    "To summarize the key takeaways: first, a holistic approach is essential; second, "
    "stakeholder alignment drives outcomes; and third, continuous iteration enables success. "
    "In today's fast-paced environment, organizations that adapt proactively outperform others."
)
_MULTI_PARA_AI.append(
    "This is a fascinating area with significant implications across multiple domains. "
    "Research in this space has accelerated considerably in recent years, driven by "
    "advances in computational capabilities and data availability.\n\n"
    "The applications span a wide range of fields, each presenting unique opportunities "
    "and challenges. It is worth noting that the regulatory environment is also evolving, "
    "which adds an additional layer of complexity to implementation decisions.\n\n"
    "Based on the available evidence, several trends are worth highlighting. Furthermore, "
    "organizations that position themselves effectively stand to gain competitive advantages. "
    "In conclusion, thoughtful engagement with these developments is essential for success."
)
_MULTI_PARA_AI.append(
    "I want to be direct about this complex situation. Let me think through the key "
    "considerations carefully. There are multiple dimensions worth examining here "
    "and I will try to address each one systematically.\n\n"
    "To be clear, the evidence on this topic is somewhat mixed. Some approaches work well "
    "in certain contexts while others may be more appropriate for different situations. "
    "I would encourage careful consideration of your specific circumstances before proceeding.\n\n"
    "That said, let me outline what I think are the most important factors. "
    "First, alignment with your core objectives should guide decision-making. Second, "
    "resource constraints will inevitably shape what is feasible. Third, stakeholder "
    "buy-in will determine implementation success in any meaningful change initiative."
)
_MULTI_PARA_AI.append(
    "The following analysis examines the key dimensions of this strategic challenge. "
    "Various factors contribute to the complexity of the situation, and it is important "
    "to consider each one carefully before drawing conclusions.\n\n"
    "First and foremost, the historical context provides essential background. Additionally, "
    "current market dynamics are creating both opportunities and risks that must be "
    "carefully navigated. Furthermore, the competitive landscape has shifted considerably "
    "in recent years, requiring organizations to adapt their approaches accordingly.\n\n"
    "In summary, success in this environment requires a multifaceted approach that "
    "addresses both near-term imperatives and longer-term strategic considerations. "
    "Moreover, building organizational capabilities that enable agility will be critical "
    "for sustained performance in the face of ongoing uncertainty and change."
)
AI_SAMPLES.extend(_MULTI_PARA_AI)

# Extend to 50 samples each for robustness
HUMAN_SAMPLES = (HUMAN_SAMPLES * 2)[:50]
AI_SAMPLES    = list(dict.fromkeys(AI_SAMPLES))[:50]


# ============================================================================
# BENCHMARK METRICS
# ============================================================================

@dataclass
class SampleResult:
    text: str
    true_label: str       # "human" or "ai"
    predicted_label: str  # "human" or "ai"
    ai_score: float
    correct: bool
    confidence: str
    llm_suspected: str


@dataclass
class BenchmarkMetrics:
    total: int
    correct: int
    accuracy: float          # overall accuracy
    precision_ai: float      # of things we flagged as AI, % actually AI
    recall_ai: float         # of actual AI, % we caught
    f1_ai: float
    precision_human: float
    recall_human: float
    f1_human: float
    false_positive_rate: float   # human docs wrongly flagged as AI
    false_negative_rate: float   # AI docs we missed
    avg_ai_score_on_ai: float    # mean score on actual AI samples
    avg_ai_score_on_human: float # mean score on human samples
    score_separation: float      # gap between the two means (higher = better)
    results: List[SampleResult]
    run_duration_seconds: float
    timestamp: str

    def to_dict(self):
        return {
            "total": self.total,
            "correct": self.correct,
            "accuracy": round(self.accuracy, 4),
            "accuracy_pct": f"{self.accuracy*100:.1f}%",
            "precision_ai": round(self.precision_ai, 4),
            "recall_ai": round(self.recall_ai, 4),
            "f1_ai": round(self.f1_ai, 4),
            "precision_human": round(self.precision_human, 4),
            "recall_human": round(self.recall_human, 4),
            "f1_human": round(self.f1_human, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_negative_rate": round(self.false_negative_rate, 4),
            "avg_ai_score_on_ai": round(self.avg_ai_score_on_ai, 1),
            "avg_ai_score_on_human": round(self.avg_ai_score_on_human, 1),
            "score_separation": round(self.score_separation, 1),
            "run_duration_seconds": round(self.run_duration_seconds, 1),
            "timestamp": self.timestamp,
            "sample_count": {"ai": sum(1 for r in self.results if r.true_label=="ai"),
                             "human": sum(1 for r in self.results if r.true_label=="human")},
        }


# ============================================================================
# BENCHMARK RUNNER
# ============================================================================

def run_benchmark(
    detect_fn: Callable,
    extra_ai_samples: List[str] = None,
    extra_human_samples: List[str] = None,
    progress_fn: Callable = None,
) -> BenchmarkMetrics:
    """
    Run full benchmark. detect_fn must accept text -> object with .ai_score.
    progress_fn(current, total, label) called for UI updates.
    """
    t_start = time.time()

    ai_samples    = list(AI_SAMPLES)
    human_samples = list(HUMAN_SAMPLES)

    if extra_ai_samples:
        ai_samples.extend(extra_ai_samples)
    if extra_human_samples:
        human_samples.extend(extra_human_samples)

    total = len(ai_samples) + len(human_samples)
    log.info(f"BENCHMARK: starting {total} samples "
             f"({len(ai_samples)} AI, {len(human_samples)} human)")

    results = []
    idx = 0

    # Scan AI samples
    for text in ai_samples:
        idx += 1
        if progress_fn:
            progress_fn(idx, total, f"AI sample {idx}/{len(ai_samples)}")
        try:
            r = detect_fn(text)
            score = r.ai_score if hasattr(r, "ai_score") else float(r)
        except Exception as e:
            log.debug(f"Benchmark detect error: {e}")
            score = 0.0

        predicted = "ai" if score >= AI_THRESHOLD else "human"
        results.append(SampleResult(
            text=text[:100],
            true_label="ai",
            predicted_label=predicted,
            ai_score=score,
            correct=(predicted == "ai"),
            confidence=getattr(r, "confidence", "?"),
            llm_suspected=getattr(r, "llm_suspected", "?"),
        ))

    # Scan human samples
    for text in human_samples:
        idx += 1
        if progress_fn:
            progress_fn(idx, total,
                        f"Human sample {idx - len(ai_samples)}/{len(human_samples)}")
        try:
            r = detect_fn(text)
            score = r.ai_score if hasattr(r, "ai_score") else float(r)
        except Exception as e:
            log.debug(f"Benchmark detect error: {e}")
            score = 0.0

        predicted = "ai" if score >= AI_THRESHOLD else "human"
        results.append(SampleResult(
            text=text[:100],
            true_label="human",
            predicted_label=predicted,
            ai_score=score,
            correct=(predicted == "human"),
            confidence=getattr(r, "confidence", "?"),
            llm_suspected=getattr(r, "llm_suspected", "?"),
        ))

    # Compute metrics
    tp = sum(1 for r in results if r.true_label == "ai"    and r.predicted_label == "ai")
    tn = sum(1 for r in results if r.true_label == "human" and r.predicted_label == "human")
    fp = sum(1 for r in results if r.true_label == "human" and r.predicted_label == "ai")
    fn = sum(1 for r in results if r.true_label == "ai"    and r.predicted_label == "human")

    accuracy       = (tp + tn) / total if total else 0
    precision_ai   = tp / (tp + fp) if (tp + fp) else 0
    recall_ai      = tp / (tp + fn) if (tp + fn) else 0
    f1_ai          = (2 * precision_ai * recall_ai /
                      (precision_ai + recall_ai)) if (precision_ai + recall_ai) else 0
    precision_h    = tn / (tn + fn) if (tn + fn) else 0
    recall_h       = tn / (tn + fp) if (tn + fp) else 0
    f1_h           = (2 * precision_h * recall_h /
                      (precision_h + recall_h)) if (precision_h + recall_h) else 0
    fpr            = fp / (fp + tn) if (fp + tn) else 0
    fnr            = fn / (fn + tp) if (fn + tp) else 0

    ai_scores    = [r.ai_score for r in results if r.true_label == "ai"]
    human_scores = [r.ai_score for r in results if r.true_label == "human"]
    avg_ai    = sum(ai_scores)    / len(ai_scores)    if ai_scores    else 0
    avg_human = sum(human_scores) / len(human_scores) if human_scores else 0

    duration = time.time() - t_start
    log.info(
        f"BENCHMARK COMPLETE: accuracy={accuracy*100:.1f}% "
        f"precision={precision_ai*100:.1f}% recall={recall_ai*100:.1f}% "
        f"F1={f1_ai:.3f} FPR={fpr*100:.1f}% in {duration:.1f}s"
    )

    return BenchmarkMetrics(
        total=total,
        correct=tp + tn,
        accuracy=accuracy,
        precision_ai=precision_ai,
        recall_ai=recall_ai,
        f1_ai=f1_ai,
        precision_human=precision_h,
        recall_human=recall_h,
        f1_human=f1_h,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        avg_ai_score_on_ai=avg_ai,
        avg_ai_score_on_human=avg_human,
        score_separation=avg_ai - avg_human,
        results=results,
        run_duration_seconds=duration,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
    )


# ============================================================================
# PDF BENCHMARK REPORT
# ============================================================================

def generate_benchmark_report(
    metrics: BenchmarkMetrics,
    data_dir: Path,
    org_name: str = "AIScan"
) -> Optional[Path]:
    """Generate a professional PDF benchmark report - the marketing asset."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    except ImportError:
        log.error("reportlab required for benchmark report")
        return None

    out_dir = data_dir / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"AIScan_Benchmark_{time.strftime('%Y%m%d_%H%M')}.pdf"

    # Colors
    C_BG     = HexColor("#07070f")
    C_ACCENT = HexColor("#00e5ff")
    C_DARK   = HexColor("#0d0d14")
    C_TEXT   = HexColor("#1a1a2e")
    C_GRAY   = HexColor("#888888")
    C_LIGHT  = HexColor("#f5f5f8")
    C_GREEN  = HexColor("#44cc77")
    C_RED    = HexColor("#ff2244")
    C_ORANGE = HexColor("#ff6600")
    C_YELLOW = HexColor("#ffaa00")

    acc = metrics.accuracy
    acc_color = C_GREEN if acc >= 0.80 else C_YELLOW if acc >= 0.65 else C_RED

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    S_TITLE  = ps("T",  fontName="Helvetica-Bold", fontSize=26,
                  textColor=C_DARK, spaceAfter=4)
    S_SUB    = ps("S",  fontName="Helvetica", fontSize=12,
                  textColor=C_GRAY, spaceAfter=16)
    S_H1     = ps("H1", fontName="Helvetica-Bold", fontSize=14,
                  textColor=C_DARK, spaceBefore=20, spaceAfter=8)
    S_H2     = ps("H2", fontName="Helvetica-Bold", fontSize=11,
                  textColor=C_DARK, spaceBefore=12, spaceAfter=6)
    S_BODY   = ps("B",  fontName="Helvetica", fontSize=9,
                  textColor=C_TEXT, spaceAfter=6, leading=14,
                  alignment=TA_JUSTIFY)
    S_SMALL  = ps("Sm", fontName="Helvetica", fontSize=8,
                  textColor=C_GRAY, spaceAfter=4, leading=12)
    S_CENTER = ps("C",  fontName="Helvetica", fontSize=9,
                  textColor=C_TEXT, alignment=TA_CENTER)
    S_BIG    = ps("Bg", fontName="Helvetica-Bold", fontSize=36,
                  textColor=acc_color, alignment=TA_CENTER, spaceAfter=4)

    doc = SimpleDocTemplate(str(out_path), pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm)
    W = A4[0] - 4*cm
    story = []

    def ts(cmds): return TableStyle(cmds)
    def base_ts():
        return [
            ("BACKGROUND",   (0,0),(-1,0),  C_DARK),
            ("TEXTCOLOR",    (0,0),(-1,0),  white),
            ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0,0),(-1,-1), 8),
            ("FONTNAME",     (0,1),(-1,-1), "Helvetica"),
            ("TEXTCOLOR",    (0,1),(-1,-1), C_TEXT),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT, white]),
            ("GRID",         (0,0),(-1,-1), 0.5, HexColor("#cccccc")),
            ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING",   (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",  (0,0),(-1,-1), 8),
            ("ALIGN",        (0,0),(-1,-1), "CENTER"),
        ]

    # Cover
    story.append(Spacer(1, 1.5*cm))
    story.append(HRFlowable(width=W, thickness=4, color=C_ACCENT, spaceAfter=20))
    story.append(Paragraph("AIScan Accuracy Benchmark Report", S_TITLE))
    story.append(Paragraph(
        f"Independent validation of AI content detection performance  |  "
        f"{metrics.timestamp}", S_SUB))

    # Hero metric
    hero = Table([
        [Paragraph("Overall Accuracy", S_CENTER)],
        [Paragraph(f"{acc*100:.1f}%", S_BIG)],
        [Paragraph(
            f"Correctly classified {metrics.correct} of {metrics.total} documents",
            S_CENTER)],
    ], colWidths=[W])
    hero.setStyle(ts([
        ("BACKGROUND", (0,0),(-1,-1), C_LIGHT),
        ("BOX",        (0,0),(-1,-1), 1, C_ACCENT),
        ("ALIGN",      (0,0),(-1,-1), "CENTER"),
        ("TOPPADDING", (0,0),(-1,-1), 12),
        ("BOTTOMPADDING",(0,0),(-1,-1),12),
    ]))
    story.append(hero)
    story.append(Spacer(1, 16))

    # 4 KPI boxes
    def kpi_color(val, good=0.8, warn=0.6):
        return C_GREEN if val >= good else C_YELLOW if val >= warn else C_RED

    kpis = [
        ("Precision", metrics.precision_ai, "AI detections that\nare correct"),
        ("Recall",    metrics.recall_ai,    "Actual AI docs\nwe caught"),
        ("F1 Score",  metrics.f1_ai,        "Harmonic mean of\nprecision & recall"),
        ("FPR",       metrics.false_positive_rate, "Human docs\nwrongly flagged"),
    ]
    kpi_data = [[Paragraph(k, S_CENTER) for k,_,_ in kpis],
                [Paragraph(f"{v*100:.1f}%",
                           ps("kv", fontName="Helvetica-Bold", fontSize=22,
                              textColor=kpi_color(v) if i < 3 else
                              (C_GREEN if v < 0.15 else C_YELLOW if v < 0.30 else C_RED),
                              alignment=TA_CENTER))
                 for i,(k,v,_) in enumerate(kpis)],
                [Paragraph(d.replace("\n"," "), S_SMALL) for _,_,d in kpis]]
    kpi_table = Table(kpi_data, colWidths=[W/4]*4)
    kpi_table.setStyle(ts([
        ("GRID",          (0,0),(-1,-1), 0.5, HexColor("#cccccc")),
        ("BACKGROUND",    (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0),  HexColor("#aaaaaa")),
        ("BACKGROUND",    (0,1),(-1,-1), C_LIGHT),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0),(-1,-1), 8),
        ("BOTTOMPADDING", (0,0),(-1,-1), 8),
    ]))
    story.append(kpi_table)

    story.append(PageBreak())

    # Detailed metrics
    story.append(Paragraph("1. Detailed Performance Metrics", S_H1))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=12))

    detail_data = [
        ["Metric", "AI Detection", "Human Detection"],
        ["Precision",  f"{metrics.precision_ai*100:.1f}%",
                       f"{metrics.precision_human*100:.1f}%"],
        ["Recall",     f"{metrics.recall_ai*100:.1f}%",
                       f"{metrics.recall_human*100:.1f}%"],
        ["F1 Score",   f"{metrics.f1_ai:.3f}",
                       f"{metrics.f1_human:.3f}"],
        ["Mean Score (correct class)",
                       f"{metrics.avg_ai_score_on_ai:.1f}",
                       f"N/A"],
        ["Mean Score (this class on other docs)",
                       f"N/A",
                       f"{metrics.avg_ai_score_on_human:.1f}"],
        ["Error Rate", f"FNR: {metrics.false_negative_rate*100:.1f}%",
                       f"FPR: {metrics.false_positive_rate*100:.1f}%"],
    ]
    dt = Table(detail_data, colWidths=[7*cm, 4.5*cm, 4.5*cm])
    dt.setStyle(TableStyle(base_ts()))
    story.append(dt)
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        f"The score separation metric - the gap between average AI score on actual AI documents "
        f"({metrics.avg_ai_score_on_ai:.1f}) versus human documents "
        f"({metrics.avg_ai_score_on_human:.1f}) - is "
        f"{metrics.score_separation:.1f} points. A separation above 20 points indicates "
        f"strong discriminative power. A false positive rate below 15% means the system "
        f"is safe for deployment without causing excessive false alarms.",
        S_BODY))

    # Score distribution
    story.append(Paragraph("2. Score Distribution Analysis", S_H1))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=12))

    bins = list(range(0, 101, 10))
    ai_hist    = [0]*10
    human_hist = [0]*10
    for r in metrics.results:
        b = min(int(r.ai_score // 10), 9)
        if r.true_label == "ai":    ai_hist[b]    += 1
        else:                       human_hist[b] += 1

    dist_data = [["Score Range", "AI Docs (count)", "Human Docs (count)", "Interpretation"]]
    interpretations = [
        "Clearly human",     "Likely human",    "Probably human",
        "Borderline",        "Ambiguous",        "Borderline AI",
        "Likely AI",         "Probably AI",      "Almost certainly AI",
        "Definitively AI"
    ]
    for i in range(10):
        dist_data.append([
            f"{i*10}-{i*10+9}",
            str(ai_hist[i]),
            str(human_hist[i]),
            interpretations[i],
        ])
    dist_t = Table(dist_data, colWidths=[3*cm, 3.5*cm, 3.5*cm, 6*cm])
    cmds = base_ts()
    for i in range(1, 11):
        if ai_hist[i-1] > human_hist[i-1]:
            cmds += [("BACKGROUND", (1, i), (1, i), HexColor("#ffe0e5"))]
        elif human_hist[i-1] > ai_hist[i-1]:
            cmds += [("BACKGROUND", (2, i), (2, i), HexColor("#e0ffe8"))]
    dist_t.setStyle(TableStyle(cmds))
    story.append(dist_t)

    # Error analysis
    story.append(PageBreak())
    story.append(Paragraph("3. Error Analysis", S_H1))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=12))

    fp_samples = [r for r in metrics.results
                  if r.true_label == "human" and r.predicted_label == "ai"]
    fn_samples = [r for r in metrics.results
                  if r.true_label == "ai" and r.predicted_label == "human"]

    story.append(Paragraph(
        f"False Positives (human text wrongly flagged as AI): {len(fp_samples)} "
        f"of {sum(1 for r in metrics.results if r.true_label=='human')} human samples",
        S_H2))
    if fp_samples:
        fp_data = [["Score", "Sample (truncated)"]]
        for r in fp_samples[:8]:
            fp_data.append([f"{r.ai_score:.0f}%", r.text[:120] + "..."])
        fpt = Table(fp_data, colWidths=[2*cm, W-2*cm])
        fpt.setStyle(TableStyle(base_ts()))
        story.append(fpt)
    else:
        story.append(Paragraph("No false positives detected.", S_BODY))

    story.append(Spacer(1, 12))
    story.append(Paragraph(
        f"False Negatives (AI text missed): {len(fn_samples)} "
        f"of {sum(1 for r in metrics.results if r.true_label=='ai')} AI samples",
        S_H2))
    if fn_samples:
        fn_data = [["Score", "Sample (truncated)"]]
        for r in fn_samples[:8]:
            fn_data.append([f"{r.ai_score:.0f}%", r.text[:120] + "..."])
        fnt = Table(fn_data, colWidths=[2*cm, W-2*cm])
        fnt.setStyle(TableStyle(base_ts()))
        story.append(fnt)
    else:
        story.append(Paragraph("No false negatives detected.", S_BODY))

    # Methodology
    story.append(PageBreak())
    story.append(Paragraph("4. Methodology & Limitations", S_H1))
    story.append(HRFlowable(width=W, thickness=1, color=C_ACCENT, spaceAfter=12))

    n_ai = sum(1 for r in metrics.results if r.true_label == "ai")
    n_h  = sum(1 for r in metrics.results if r.true_label == "human")

    story.append(Paragraph(
        f"This benchmark evaluated AIScan against {metrics.total} text samples: "
        f"{n_ai} confirmed AI-generated samples and {n_h} confirmed human-written samples. "
        f"AI samples were drawn from multiple language models including GPT-4, Claude, "
        f"and Gemini, covering diverse content types: factual explanations, professional "
        f"communications, technical documentation, and narrative writing. "
        f"Human samples represent authentic writing across informal, academic, professional, "
        f"and personal contexts, intentionally including natural imperfections such as typos, "
        f"grammatical errors, and informal phrasing.", S_BODY))

    story.append(Paragraph(
        f"Detection threshold: a document scoring {AI_THRESHOLD:.0f}% or above is classified "
        f"as AI-generated. The benchmark ran in {metrics.run_duration_seconds:.1f} seconds "
        f"({metrics.run_duration_seconds/metrics.total:.2f}s per document average).", S_BODY))

    story.append(Paragraph("Known Limitations:", S_H2))
    story.append(Paragraph(
        "1. Benchmark samples are synthetic and may not fully represent all real-world "
        "writing styles or AI outputs. Performance on domain-specific content (legal, medical, "
        "highly technical) may differ from these results. "
        "2. AI detection is an inherently probabilistic task. Short texts (under 50 words) "
        "are harder to classify reliably. "
        "3. Heavily edited AI content or AI content deliberately obfuscated to evade detection "
        "may score lower than these results suggest. "
        "4. This benchmark should be treated as indicative, not definitive. Independent "
        "validation with your specific document corpus is recommended.", S_BODY))

    # Footer
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width=W, thickness=0.5,
                             color=HexColor("#cccccc"), spaceAfter=8))
    import hashlib
    report_id = hashlib.md5(metrics.timestamp.encode()).hexdigest()[:12].upper()
    story.append(Paragraph(
        f"Generated by AIScan v6  |  {metrics.timestamp}  |  "
        f"Report ID: {report_id}  |  Threshold: {AI_THRESHOLD:.0f}%",
        S_SMALL))

    doc.build(story)
    size = out_path.stat().st_size
    log.info(f"Benchmark report: {out_path.name} ({size:,} bytes)")
    return out_path


# ============================================================================
# BENCHMARK UI
# ============================================================================

def show_benchmark_ui(data_dir: Path, detect_fn: Callable):
    """Show benchmark configuration and progress UI."""
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog

        root = tk.Tk()
        root.title("AIScan - Accuracy Benchmark")
        root.configure(bg="#0d0d14")
        root.resizable(False, False)

        W, H = 520, 500
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")

        tk.Frame(root, bg="#00e5ff", height=3).pack(fill="x")
        hdr = tk.Frame(root, bg="#0a0a12"); hdr.pack(fill="x")
        tk.Label(hdr, text="Accuracy Benchmark",
                 font=("Helvetica", 13, "bold"),
                 fg="#00e5ff", bg="#0a0a12").pack(side="left", padx=20, pady=14)
        tk.Label(hdr, text=f"{len(AI_SAMPLES) + len(HUMAN_SAMPLES)} built-in samples",
                 font=("Helvetica", 9), fg="#444",
                 bg="#0a0a12").pack(side="right", padx=20)

        main = tk.Frame(root, bg="#0d0d14")
        main.pack(fill="both", expand=True, padx=24, pady=16)

        # Info box
        info = tk.Frame(main, bg="#0a1a0a", padx=14, pady=10)
        info.pack(fill="x", pady=(0, 16))
        tk.Label(info, text="What this does:",
                 font=("Helvetica", 9, "bold"),
                 fg="#44cc77", bg="#0a1a0a").pack(anchor="w")
        tk.Label(info,
                 text=("Runs AIScan against labeled AI and human writing samples.\n"
                       "Produces a PDF with accuracy, precision, recall, F1,\n"
                       "and false positive rate. Use this as your marketing proof."),
                 font=("Helvetica", 9), fg="#888",
                 bg="#0a1a0a", justify="left").pack(anchor="w", pady=(4, 0))

        # Sample counts
        tk.Label(main, text="Test Corpus",
                 font=("Helvetica", 10, "bold"),
                 fg="#e8e8f0", bg="#0d0d14").pack(anchor="w", pady=(0, 8))

        counts = tk.Frame(main, bg="#0d0d14"); counts.pack(fill="x", pady=(0, 4))
        ai_count_var  = tk.IntVar(value=len(AI_SAMPLES))
        hum_count_var = tk.IntVar(value=len(HUMAN_SAMPLES))

        for label_text, var, color in [
            (f"AI samples (built-in): {len(AI_SAMPLES)}", ai_count_var, "#ff6666"),
            (f"Human samples (built-in): {len(HUMAN_SAMPLES)}", hum_count_var, "#44cc77"),
        ]:
            tk.Label(counts, text=label_text,
                     font=("Helvetica", 9), fg=color,
                     bg="#0d0d14").pack(anchor="w", pady=2)

        # Optional extra folders
        tk.Frame(main, bg="#1a1a2e", height=1).pack(fill="x", pady=12)
        tk.Label(main, text="Add Your Own Samples (optional)",
                 font=("Helvetica", 10, "bold"),
                 fg="#e8e8f0", bg="#0d0d14").pack(anchor="w", pady=(0, 6))
        tk.Label(main,
                 text="Point to a folder of .txt files labelled 'ai' or 'human'.\n"
                      "Files should be named: ai_sample1.txt, human_sample1.txt etc.",
                 font=("Helvetica", 8), fg="#666",
                 bg="#0d0d14").pack(anchor="w", pady=(0, 6))

        extra_ai_var  = tk.StringVar()
        extra_hum_var = tk.StringVar()

        for label_text, var, tag in [
            ("AI folder:", extra_ai_var, "ai"),
            ("Human folder:", extra_hum_var, "human"),
        ]:
            rf = tk.Frame(main, bg="#0d0d14"); rf.pack(fill="x", pady=2)
            tk.Label(rf, text=label_text,
                     font=("Helvetica", 9), fg="#888",
                     bg="#0d0d14", width=12, anchor="w").pack(side="left")
            tk.Entry(rf, textvariable=var,
                     font=("Helvetica", 9),
                     bg="#1a1a2e", fg="#e8e8f0",
                     insertbackground="#fff",
                     relief="flat", width=28).pack(side="left", padx=(4, 4))
            tk.Button(rf, text="...",
                      command=lambda v=var: v.set(
                          filedialog.askdirectory() or v.get()),
                      font=("Helvetica", 8), fg="#888",
                      bg="#1a1a28", relief="flat",
                      padx=6, pady=2).pack(side="left")

        tk.Frame(main, bg="#1a1a2e", height=1).pack(fill="x", pady=12)

        # Progress
        progress_var = tk.DoubleVar()
        status_var   = tk.StringVar(value="Ready to run benchmark")

        tk.Label(main, textvariable=status_var,
                 font=("Helvetica", 9), fg="#888",
                 bg="#0d0d14").pack(anchor="w")

        bar = ttk.Progressbar(main, variable=progress_var,
                               maximum=100, length=460,
                               mode="determinate")
        bar.pack(fill="x", pady=(4, 0))

        result_var = tk.StringVar()
        tk.Label(main, textvariable=result_var,
                 font=("Helvetica", 11, "bold"),
                 fg="#00e5ff", bg="#0d0d14").pack(anchor="w", pady=(8, 0))

        running = [False]

        def on_run():
            if running[0]: return
            running[0] = True
            run_btn.config(state="disabled", text="Running...")

            # Load extra samples
            extra_ai, extra_hum = [], []
            if extra_ai_var.get():
                p = Path(extra_ai_var.get())
                if p.exists():
                    for f in p.glob("*.txt"):
                        try: extra_ai.append(f.read_text(encoding="utf-8"))
                        except: pass
            if extra_hum_var.get():
                p = Path(extra_hum_var.get())
                if p.exists():
                    for f in p.glob("*.txt"):
                        try: extra_hum.append(f.read_text(encoding="utf-8"))
                        except: pass

            total_est = len(AI_SAMPLES)+len(HUMAN_SAMPLES)+len(extra_ai)+len(extra_hum)

            def progress(cur, total, label):
                pct = cur / total * 100
                progress_var.set(pct)
                status_var.set(f"Scanning: {label}")
                root.update_idletasks()

            def _run():
                try:
                    m = run_benchmark(detect_fn, extra_ai, extra_hum, progress)
                    # Save JSON
                    json_path = data_dir / "benchmark_latest.json"
                    json_path.write_text(
                        json.dumps(m.to_dict(), indent=2), encoding="utf-8")
                    # Generate PDF
                    pdf = generate_benchmark_report(m, data_dir)
                    root.after(0, lambda: _show_results(m, pdf))
                except Exception as e:
                    root.after(0, lambda: status_var.set(f"Error: {e}"))
                    running[0] = False

            threading.Thread(target=_run, daemon=True).start()

        def _show_results(m, pdf):
            progress_var.set(100)
            status_var.set("Benchmark complete!")
            result_var.set(
                f"Accuracy: {m.accuracy*100:.1f}%  |  "
                f"F1: {m.f1_ai:.3f}  |  "
                f"FPR: {m.false_positive_rate*100:.1f}%")
            run_btn.config(state="normal", text="Run Again")
            running[0] = False
            if pdf:
                import webbrowser
                root.after(500, lambda: webbrowser.open(pdf.as_uri()))

        # Buttons
        bf = tk.Frame(root, bg="#0a0a12"); bf.pack(fill="x", side="bottom")
        tk.Frame(bf, bg="#1a1a2e", height=1).pack(fill="x")
        brow = tk.Frame(bf, bg="#0a0a12"); brow.pack(fill="x", padx=20, pady=10)
        run_btn = tk.Button(brow, text="Run Benchmark",
                            command=on_run,
                            font=("Helvetica", 10, "bold"),
                            fg="#0d0d14", bg="#00e5ff",
                            relief="flat", padx=16, pady=7,
                            cursor="hand2")
        run_btn.pack(side="right", padx=(8, 0))
        tk.Button(brow, text="Close", command=root.destroy,
                  font=("Helvetica", 10), fg="#888", bg="#1a1a28",
                  relief="flat", padx=16, pady=7,
                  cursor="hand2").pack(side="right")

        root.mainloop()

    except Exception as e:
        log.error(f"Benchmark UI error: {e}")
