#regex module 
import re

#checks for weird spacing creates a compliled regex object
_SPACE_RE = re.compile(r'\s+')
#input: name (raw display name from email header)
#cfg: config dict 
#outputs a normalized string you can compare directly 
def normalize_display_name(name: str, cfg: dict) -> str:
   #remove white space
    name = (name or "").strip()
    norm_cfg = cfg.get("normalize", {})
    if norm_cfg.get("collapse_spaces", True):
        #replace multiple spaces with single space
        name = _SPACE_RE.sub(" ", name)
    if norm_cfg.get("casefold", True):
        name = name.casefold()
        return name

#Helper function that returns a dict
def build_normalized_alias_map(cfg: dict) -> dict: 
    #fetches the "aliases" section from config  
    alias_cfg = cfg.get("display_name_aliases", {})
    norm_map = {}
    for alias, canonical in alias_cfg.items():
       alias_norm = normalize_display_name(alias, cfg)
       norm_map[alias_norm] = canonical
    return norm_map


def resolve_canonical_identity(display_name: str, cfg: dict) -> str:
    name_norm = normalize_display_name(display_name, cfg)
    alias_map = build_normalized_alias_map(cfg)
    return alias_map.get(name_norm, name_norm)
