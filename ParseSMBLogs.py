# File: ParseSMBLogs.py
import csv
import json

# Input log file and output matrix file
input_file = "data/SMBStatusLogs.csv"  # Ensure alignment with actual folder structure
output_file = "data/SMBInventoryMatrix.json"

# Initialize risk assessment levels
risk_criteria = {
    "High": lambda row: row["EnableSMB1Protocol"] == "True",
    "Medium": lambda row: row["EnableSMB2Protocol"] == "True",
    "Low": lambda row: row["EnableSMB3Protocol"] == "True"
}

# Parse CSV and generate risk inventory
inventory = []
with open(input_file, mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        # Determine risk level
        risk = "Unknown"
        for level, condition in risk_criteria.items():
            if condition(row):
                risk = level
                break

        # Assign criticality based on risk level
        criticality = "High" if risk == "High" else "Medium" if risk == "Medium" else "Low"

        # Append all details to inventory
        inventory.append({
            "Endpoint": row.get("Endpoint", "N/A"),
            "SourceIP": row.get("SourceIP", "N/A"),  # Ensure key exists in CSV
            "DestinationIP": row.get("DestinationIP", "N/A"),
            "Hostname": row.get("Hostname", "N/A"),
            "ServicePort": row.get("ServicePort", "N/A"),
            "EnableSMB1Protocol": row.get("EnableSMB1Protocol", "N/A"),
            "EnableSMB2Protocol": row.get("EnableSMB2Protocol", "N/A"),
            "EnableSMB3Protocol": row.get("EnableSMB3Protocol", "N/A"),
            "RiskLevel": risk,
            "Criticality": criticality
        })

# Save inventory to JSON
with open(output_file, mode="w") as file:
    json.dump(inventory, file, indent=4)

print(f"Inventory matrix saved to {output_file}.")
