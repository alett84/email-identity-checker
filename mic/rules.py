# mic/rules.py

def rule_protected_identity_mismatch(ctx: dict, cfg: dict):
    canonical = ctx.get("canonical_identity", "")
    from_addr = (ctx.get("from_addr") or "").strip().lower()

    protected = cfg.get("protected_identities", {})
    if canonical not in protected:
        return None

    allowed_addrs = {a.strip().lower() for a in protected.get(canonical, [])}
    if from_addr in allowed_addrs:
        return None

    weights = cfg.get("identity_weights", {})
    weight = weights.get(canonical, 5)

    base_points = 80
    points = min(100, int(base_points * (weight / 10)))

    return {
        "rule": "PROTECTED_IDENTITY_MISMATCH",
        "points": points,
        "message": (
            f'Display name matches protected identity "{canonical}" '
            f'but sender address "{from_addr}" is not allowed.'
        ),
    }


def rule_sensitive_info_request(ctx: dict, cfg: dict): 
    
    body = (ctx.get("body") or "").lower()
   
    if not body: 
        return None
    suspicious_keywords = [ 
        "social security", 
        "ssn", 
        "routing number", 
        "bank account", 
        "direct deposit", 
        "mother", 
        "maiden name"
    ]
    matches = [k for k in suspicious_keywords if k in body]

    if not matches: 
         return None 

    return {
        "rule" : "SENSITIVE_INFORMATION_REQUEST", 
        "points" : "50", 
        "message" : f"Email requests sensitive information: {', '.join(matches)}"
        }
    
#In progress
#def rule_external_internal_impersonation(ctx: dict, cfg: dict): 
#    print("IM RUNNING")
#    from_addr = (ctx.get("from_addr") or "").lower()
#    from_name = (ctx.get("from_name") or "").lower()
#    body = (ctx.get("body") or "").lower()
#    print(repr(body))

#    company_domain = cfg.get("company_domain", "").lower()

#    dept_keywords = ["payroll", "hr", "finance", "accounting"]

#    if company_domain and not from_addr.endswith(company_domain):
#        name_hit = any(word in from_name for word in dept_keywords)
#        body_hit = any(
#            re.search(rf"\b{word}\b", body)
#            for word in dept_keywords
#            )


#        if name_hit or body_hit:
#
#            return{
#
#                "rule" : "EXTERNAL_INTERNAL_IMPERSONATION", 
#                "points" : "40", 
#                "message" : "External sender appears to impersonate internal department"
#            }
    
#    return None