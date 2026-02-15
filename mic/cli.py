import argparse
import json
import sys
import logging
from mic.config import load_config, ConfigError
from mic.parse_email import load_eml, parse_message
from mic.identity import resolve_canonical_identity
from mic.rules import rule_protected_identity_mismatch, rule_sensitive_info_request
from mic.score import score_email


#returns a argumentParser instance
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='mic',
        description='Mails Identity Correlator - analyze email sender identities against known mappings.'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    analyze = sub.add_parser('analyze', help='Analyze an .eml file and print a verdict')
    analyze.add_argument('eml_path', type=str, help='Path to the .eml file to analyze')
    analyze.add_argument('--config', "-c", required=True, help="Path to identities.yml")
    analyze.add_argument("--json", action="store_true", help="Output result as JSON instead of plain text")

    return parser


#converts verdicts into exit codes
def verdict_exit_code(verdict: str) -> int:
    if verdict == "allow":
        return 0
    if verdict == "tag":
        return 10
    if verdict == "quarantine":
        return 20
    return 2  #unknown verdict


def run_analyse(eml_path: str, config_path: str) -> dict:
    #load YAML config and validate
    cfg = load_config(config_path)

    #read email into EmailMessage object
    msg = load_eml(eml_path)

    #extract fields into context dict
    ctx = parse_message(msg)

    #add canonical identity to context
    ctx["canonical_identity"] = resolve_canonical_identity(ctx["from_name"], cfg)

    #run the rule list and produces score/verdict/reasons
    result = score_email(ctx, cfg, rules=[rule_protected_identity_mismatch, rule_sensitive_info_request])

    result["Context"] = ctx
    return result


#main entry point
#Return an integer exit code
def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]

    #configure logging (timestamped audit log)
    logging.basicConfig(
        filename="analysis.log",
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    #build parser and parse the arguments into args
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    #for catching errors
    try:
        if args.command == "analyze":
            result = run_analyse(args.eml_path, args.config)

            #log rule triggers with timestamps
            for r in result.get("reasons", []):
                logging.info(
                    f"Rule triggered: {r['rule']} | "
                    f"Points: +{r['points']} | "
                    f"Message: {r['message']}"
                )

            #log final verdict
            logging.info(
                f"Final verdict: {result['verdict']} | Total score: {result['score']}"
            )

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"Verdict: {result['verdict']}")
                print(f"Score: {result['score']}")

                if result["reasons"]:
                    print("\nReasons:")
                    for r in result["reasons"]:
                        print(f'- {r["rule"]}: +{r["points"]} ({r["message"]})')

            return verdict_exit_code(result["verdict"])

        print("No command provided", file=sys.stderr)
        return 2

    except ConfigError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"File Not Found: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())