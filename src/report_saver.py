import json
from datetime import datetime

def save_report(result):
    """save analysis resultls to timestamped JSON file
    :param result: Analysis results dictionary"""

    # Create filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"password_report_{timestamp}.json"

    #remove sensitive data
    report_data = result.copy()
    report_data.pop("masked_password", None)

    #save to file
    with open(filename, 'w') as f:
        json.dump(report_data, f, indent=2)
    return filename