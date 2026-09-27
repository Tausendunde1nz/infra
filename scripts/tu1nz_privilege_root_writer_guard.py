"""Pure evidence classifier; neither broker nor live remediation.

A NOT_THIS_FINDING result is not an authorization or a general safety verdict.
Missing or ambiguous sandbox evidence remains REVIEW_REQUIRED.
"""

UNITS = tuple("trendwatch2-" + n + ".service" for n in
              ("morning", "midday", "afternoon", "evening"))
SCRIPT = "/usr/local/bin/trendwatch_post.sh"
PARENT = "/opt/trendwatch"
TARGET = PARENT + "/today_title.txt"


def classify(evidence):
    try:
        if evidence["collector_uid"] != 1001:
            return "REVIEW_REQUIRED"
        parent = evidence["files"][PARENT]
        if parent["symlink"] or parent["path"] != PARENT:
            return "REVIEW_REQUIRED"
        write = evidence["fixed_write_verified"]
        if write["mkdir_line_23"] is not True or write["tee_line_24"] is not True:
            return "REVIEW_REQUIRED"
        for name in UNITS:
            unit = evidence["units"][name]
            service = unit["service"]
            if unit["execstart_exact_fixed_script"] is not True:
                return "REVIEW_REQUIRED"
            if service["User"] not in ("", "root", "0"):
                return "NOT_THIS_FINDING"
            if unit["timer"]["ActiveState"] != "active":
                return "REVIEW_REQUIRED"
            if service["ProtectSystem"] != "no" or service["RootDirectory"] or service["RootImage"]:
                return "REVIEW_REQUIRED"
            if any(service[k] for k in ("ReadOnlyPaths", "ReadWritePaths", "InaccessiblePaths", "DropInPaths")):
                return "REVIEW_REQUIRED"
        if parent["uid"] != 1001 or parent["writable_by_collector"] is not True:
            return "NOT_THIS_FINDING"
        if parent["mode"] != "0755":
            return "REVIEW_REQUIRED"
        return "BLOCKED_ROOT_WRITE_THROUGH_CHATOPS_DIRECTORY"
    except (KeyError, TypeError):
        return "REVIEW_REQUIRED"
