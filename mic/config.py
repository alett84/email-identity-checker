# mic/config.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple
import re

import yaml

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

#Lets us catch config porblems seperately from other bugs 
#ValueError is a good base class since its a built-in exception for bad values
#in cli "print ConfigError" 
class ConfigError(ValueError):
    pass

#"Given a dictionary 'd', make sure it contains 'key', and that the value stored at that key is of the type we expect" 
#
def _require(d: dict, key: str, expected_type: type):
    #Check if key is in dictionary
    if key not in d:
        #Stop execution and raise an error if key is missing
        raise ConfigError(f"Missing required config key: {key}")
    #Get the value stored at that key
    value = d[key]  # <-- MUST be at this indentation level (4 spaces)
    #Check if the value is of the expected type
    if not isinstance(value, expected_type):
        raise ConfigError(
            f'Config key "{key}" must be {expected_type.__name__}, '
            f"got {type(value).__name__}"
        )
    #gives the caller the validated value 
    return value


def _as_lower_str_list(value: Any, key_name: str) -> List[str]:
    if value is None: 
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ConfigError(f'Config key "{key_name}" must be a list of strings')
    seen = set()
    out = []
    for x in value: 
        s = x.strip().lower()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


#Takes a list of domain strings and validates them
#no return    
def _validate_domains(domains: List[str], key_name: str) -> None: 
    #loop through each domain string
    for d in domains: 
        #Check for invalid characters in domain string
        if "://" in d or " " in d or "/" in d:
            #If found throw error
            raise ConfigError(f'Invalid domain "{d}" in "{key_name}"')
        #Check if domain starts or ends with a dot
        if d.startswith(".") or d.endswith("."):
            raise ConfigError(f'Invalid domain "{d}" in "{key_name}"')
        
#input is whatever came from protected_indentites 
#output is a python dict with key:indetity name(str), value:list of emails (str)
def _normalize_identity_map(raw:Any) -> Dict[str, List[str]]:
    #if the input is not a dict raise error
    if not isinstance(raw, dict):
        raise ConfigError('Config key "protected_identities" must be a mapping')
    #create output dict
    out: Dict[str, List[str]] = {}
    #loop through each key-value pair in input dict
    for ident, emails in raw.items():
        #ensures key is a non-empty string
        if not isinstance(ident, str) or not ident.strip():
            raise ConfigError('protected_identities keys must be non-empty strings')
        #remove outside whitespace from key
        ident_key = ident.strip()

        #print(f"DEBUG _normalize_identity_map key={ident_key!r} type={type(emails).__name__} value={emails!r}")


        #if value is NULL treat it as an empty list
        if emails is None:
            emails_list: List[str] = []
        #if its not NONE it must be a list of strings
        else:
            if not isinstance(emails, list) or not all(isinstance(e, str) for e in emails):
                raise ConfigError(
                    f'protected_identities["{ident_key}"] must be a list of email strings'
                )

            #build a clean list of emails
            emails_list = []
            #used to remove duplicates
            seen: Set[str] = set()
            #Strip whitespace
            #lowercase
            for e in emails:
                em = e.strip().lower()
                #skip empty ones
                if not em:
                    continue

                #check for @
                if "@" not in em:
                    raise ConfigError(
                        f'Invalid email "{em}" under identity "{ident_key}"(missing "@")'
                    )

                #more validation with regex, prevents broken strings
                if not EMAIL_RE.match(em):
                    raise ConfigError(
                        f'Invalid email "{em}" under identity "{ident_key}"'
                    )

                #deduplicate emails while keeping order
                if em not in seen:
                    seen.add(em)
                    emails_list.append(em)

        #store normalized list for this identity
        out[ident_key] = emails_list

    #after processing everything, make sure we got at least one identity
    if not out:
        raise ConfigError(
            'Config "protected_identities" must not be empty'
        )
    #return normalized mapping
    return out
#Takes display_name_aliases and returns a dict alias _> canonical 
def _normalize_aliases(raw: Any) -> Dict[str, str]:
    if raw is None: 
        #if aliases are missing return empty dict
        return {}
    if not isinstance(raw, dict):
        raise ConfigError('Config key "display_name_aliases" must be a mapping (alias -> canonical)')
        #output dict
    out: Dict[str, str] = {}
    #loop through mapping entries
    for alias, canon in raw.items(): 
        #check if empty
        if not isinstance(alias, str) or not alias.strip():
            raise ConfigError('display_name_aliases keys must be non-empty strings')
        if not isinstance(canon, str) or not canon.strip():
            raise ConfigError(f'display_name_aliases["{alias}"] must be a non-empty string')
        #strip whitespace
        a = alias.strip()
        c = canon.strip()
        #store in output dict
        out[a] = c
    #return normalized mapping
    return out

def _normalize_weights(raw: Any) -> Dict[str, float]:
    #if none return empty dict
    if raw is None: 
        return {}
    if not isinstance(raw, dict):
        raise ConfigError('Config key "identity_weights" must be a mapping (identity -> float)')
        #output dict
    out: Dict[str, float] = {}
    #loop through each weight entry
    for ident , w in raw.items(): 
        if not isinstance(ident, str) or not ident.strip():
            raise ConfigError('identity_weights keys must be non-empty strings')
        if not isinstance(w, float):
            raise ConfigError(f'identity_weights["{ident}"] must be a float')
        if w < 1.0: 
            raise ConfigError(f'identity_weights["{ident}"] must be >= 1.0')
            #store stripped ident name 
            out[ident.strip()] = w
            #return weights 
    
    return out

def _normalize_thresholds(raw: Any) -> Dict[str, float]:
    #creates default so config can omit them 
    #missing thresholds? use defualt 
    default = {"quarantine": 80.0, "tag": 40.0}
    if raw is None: 
        return default
    if not isinstance(raw, dict):
        raise ConfigError('Config key "score_thresholds" must be a mapping')
        #start with defaults then override if provided 
    out =dict(default)
        #For each threshold key if provided gets its value 
    for k in ("quarantine", "tag"):
        if k in raw: 
            v = raw[k]
        if not isinstance(v, float):
            raise ConfigError(f'score_thresholds["{k}"] must be a float')
        if v < 0.0 or v > 100.0:
                raise ConfigError(f'score_thresholds["{k}"] must be between 0.0 and 100.0')
        out[k] = v
                #return normalized thresholds
    if out["tag"] > out["quarantine"]:
        raise ConfigError('score_thresholds["tag"] must be less than or equal to score_thresholds["quarantine"]')
    return out

#input is a path to a yaml config file
#returns a mapping where keys are strings and values can be anything 

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    #basic top-level validation
    if not isinstance(raw, dict):
        raise ConfigError("Config file must contain a top-level mapping")

    #Domains listed below 
    # are either from our own organization or from trusted partners.
    org_domains = _as_lower_str_list(_require(raw, "org_domains", list), "org_domains")
    if not org_domains:
        raise ConfigError('Config key "org_domains" must not be empty')

    exempt_domains = _as_lower_str_list(raw.get("exempt_domains"), "exempt_domains")

    #List of identities that are protected from de-identification
    #IMPORTANT: this must only be normalized using _normalize_identity_map
    protected_identities_raw = raw.get("protected_identities")
    protected_identities = _normalize_identity_map(protected_identities_raw)

    #Mapping of display names to aliases for de-identification
    #IMPORTANT: aliases are alias -> canonical (strings), NOT lists of emails
    display_name_aliases_raw = raw.get("display_name_aliases")
    display_name_aliases = _normalize_aliases(display_name_aliases_raw)

    #Weights assigned to each identity for impersonation score 
    identity_weights = _normalize_weights(raw.get("identity_weights"))

    #Thresholds for impersonation scores
    score_thresholds = _normalize_thresholds(raw.get("score_thresholds"))

    #normalize options
    normalize = raw.get("normalize", {})

    return {
        "org_domains": org_domains,
        "org_domain_set": set(org_domains),
        "exempt_domains": exempt_domains,
        "exempt_domain_set": set(exempt_domains),
        "protected_identities": protected_identities,
        "display_name_aliases": display_name_aliases,
        "identity_weights": identity_weights,
        "score_thresholds": score_thresholds,
        "normalize": normalize,
    }

    

            

