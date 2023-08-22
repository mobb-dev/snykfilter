import json

def check_issue_type(name: str):
    # Convert the input name to lowercase for case-insensitive comparison
    name = name.lower()

    # Check against a whitelist of issue types
    # TODO: add here your relevant types from the original report
    if name in {"sqli", "sql_injection", "sql-injection", "concatenated-sql-query", "sql injection", "command-line-injection-local", "command-line-injection", "command_injection", "indirectcommandinjection", "commandinjection", "command injection"}:
        return True


def filter_report_snyk(data_dict):
    # Filter the results based on ruleIds
    filtered_results = []
    rule_id_counts = {}

    for result in data_dict["runs"][0]["results"]:
        rule_id_parts = result["ruleId"].split("/")
        rule_id = rule_id_parts[1]
        if check_issue_type(rule_id) != None:
            if rule_id not in rule_id_counts:
                rule_id_counts[rule_id] = 1
            else:
                rule_id_counts[rule_id] += 1
            if rule_id_counts[rule_id] <= 5:
                filtered_results.append(result)
    
    data_dict["runs"][0]["results"] = filtered_results

    # Convert the filtered data back to JSON
    filtered_json_data = json.dumps(data_dict, indent=2)

    # Print the filtered JSON data
    return filtered_json_data


report_file = "snyk_report.json"
filtered_report_file = "snyk_report_filtered.json"

with open(report_file, "r") as f:
    data = f.read()

filtered_data = filter_report_snyk(json.loads(data))
with open(filtered_report_file, "w") as f:
    f.write(filtered_data)
