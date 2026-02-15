# mic/score.py

def score_email(ctx: dict, cfg: dict, rules: list) -> dict:
    """
    Run all rules against the email context and return
    a final score, verdict, and list of reasons.
    """

    reasons = []
    score = 0

    # Run each rule
    for rule in rules:
        result = rule(ctx, cfg)

        # Rule did not trigger
        if result is None:
            continue

        reasons.append(result)
        score += int(result.get("points", 0))

    # Clamp score to 0–100
    score = max(0, min(100, score))

    # Load thresholds from config (with defaults)
    thresholds = cfg.get("score_thresholds", {})
    quarantine_th = int(thresholds.get("quarantine", 80))
    tag_th = int(thresholds.get("tag", 50))

    # Decide verdict
    verdict = "allow"
    if score >= quarantine_th:
        verdict = "quarantine"
    elif score >= tag_th:
        verdict = "tag"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
