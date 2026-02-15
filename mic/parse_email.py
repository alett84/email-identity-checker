#purpose is to extract the claimed sender 
#parser = facts 
#rules = judgment 
from email import policy 
from email.parser import BytesParser
from email.utils import parseaddr

#returns a message object
def load_eml(path: str): 
    #read in binary mode
    with open(path, 'rb') as f:
    #Creates a parser instance with default policy 
    #reads the file object parses headers and body returns a message object
    #Behaves like a dictionary for headers 
     return BytesParser(policy=policy.default).parse(f)

#helper function to normalize email addresses
def _norm_email(addr: str) -> str:
    #remove white space convert to lowercase
   return (addr or "").strip().lower()

#extracts domain from email address
def _domain(addr: str) -> str:
    #reuse normalization function
    addr = _norm_email(addr)
    #split at first @ 
    return addr.split("@", 1)[1] if "@" in addr else ""

#takes an EmailMessage object returns a plain python dictionary with extracted fields
#'parseaddr' splits email address into (name, address)
def parse_message(msg) -> dict:
    #look for "From" 
    from_name, from_addr = parseaddr(msg.get("From", "") or "")
    #look for "Reply-To"
    rt_name, rt_addr = parseaddr(msg.get("Reply-To", "") or "")
    #Look for subject
    subject = (msg.get("Subject", "") or "").strip()
    #Authentication results header
    #lots of gateways inject this header
    auth_results = (msg.get("Authentication-Results", "") or "").strip()
    #Extract body 
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition") or "")

            #we just want the plaintext , no attachments yet 
            if content_type == "text/plain" and "attachment" not in content_disposition:
                try:
                    payload = part.get_payload(decode = True)
                    if payload:
                        body += payload.decode(errors = "ignore")
                except Exception:
                        continue
    else:
        try:
            payload = msg.get_payload(decode = True)
            if payload: 
                body = payload.decode(errors = "ignore ")
        except Exception:
            body = ""

    return {
        "from_name": (from_name or "").strip(),
        "from_addr": _norm_email(from_addr),
        "from_domain": _domain(from_addr),
        "rt_name": (rt_name or "").strip(),
        "rt_addr": _norm_email(rt_addr),
        "rt_domain": _domain(rt_addr),
        "subject": subject,
        "auth_results": auth_results,  
        "body" : body
    }

