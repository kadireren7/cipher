#!/usr/bin/env python3
"""Collect immutable GitHub campaign evidence; incomplete/failed jobs never count as passes.

Usage: python3 scripts/collect-campaign.py tor RUN_ID [--download]
       python3 scripts/collect-campaign.py fuzz RUN_ID [--download]
Logs/corpora stay in ignored release-artifacts; a compact summary can be committed separately.
"""
import argparse
import json
import pathlib
import subprocess


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def summarize(kind, run, jobs):
    selected = [j for j in jobs if (
        j["name"].startswith("android over real Tor to onion relays") if kind == "tor"
        else j["name"].startswith("fuzz (")
    )]
    passed = sum(j.get("conclusion") == "success" for j in selected)
    completed = sum(j.get("status") == "completed" for j in selected)
    measured = kind == "tor" and len(selected) >= 20 and completed == len(selected)
    return {
        "kind": kind, "run_id": run["id"], "commit": run["head_sha"],
        "url": run["html_url"], "run_attempt": run["run_attempt"],
        "status": run["status"], "conclusion": run.get("conclusion"),
        "scheduled": len(selected), "completed": completed, "passed": passed,
        "tor_measurement_complete": measured,
        "tor_non_success_rate": (len(selected) - passed) / len(selected) if measured else None,
        "jobs": [{k: j.get(k) for k in (
            "id", "name", "status", "conclusion", "started_at", "completed_at", "html_url"
        )} for j in selected],
        "review": "Every non-success requires log triage; a fuzz pass is not independent review.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=["tor", "fuzz"])
    parser.add_argument("run_id", type=int)
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    repo = json.loads(gh("repo", "view", "--json", "nameWithOwner"))["nameWithOwner"]
    base = f"repos/{repo}/actions/runs/{args.run_id}"
    run = json.loads(gh("api", base))
    # Never mix retries into the original measurement.
    pages = json.loads(gh("api", "--paginate", "--slurp", f"{base}/attempts/{run['run_attempt']}/jobs?per_page=100"))
    jobs = [j for page in pages for j in page["jobs"]]
    result = summarize(args.kind, run, jobs)
    out = pathlib.Path(__file__).resolve().parent.parent / "release-artifacts" / f"{args.kind}-{args.run_id}-attempt-{run['run_attempt']}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "run.json").write_text(json.dumps(run, indent=2) + "\n")
    (out / "jobs.json").write_text(json.dumps(jobs, indent=2) + "\n")
    if args.download:
        subprocess.run(["gh", "run", "download", str(args.run_id), "--dir", str(out / "artifacts")], check=True)
        for job in result["jobs"]:
            if job["status"] == "completed" and job["conclusion"] != "success":
                proc = subprocess.run(["gh", "run", "view", str(args.run_id), "--job", str(job["id"]), "--log-failed"], text=True, capture_output=True)
                (out / f"job-{job['id']}-failed.txt").write_text(proc.stdout + proc.stderr)
                if proc.returncode:
                    raise SystemExit(f"Failed to retrieve job {job['id']} logs; triage is incomplete")
    print(json.dumps(result, indent=2))
    print(f"Evidence directory: {out}")


if __name__ == "__main__":
    main()
