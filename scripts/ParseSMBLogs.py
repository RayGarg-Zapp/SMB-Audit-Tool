# File: ParseSMBLogs.py
import csv
import json

# Input log file and output matrix file
input_file = "SMBStatusLogs.csv"
output_file = "SMBInventoryMatrix.json"

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
        risk = "Unknown"
        for level, condition in risk_criteria.items():
            if condition(row):
                risk = level
                break
        
        inventory.append({
            "Endpoint": row["Endpoint"],
            "EnableSMB1Protocol": row["EnableSMB1Protocol"],
            "EnableSMB2Protocol": row["EnableSMB2Protocol"],
            "EnableSMB3Protocol": row["EnableSMB3Protocol"],
            "RiskLevel": risk
        })

# Save inventory to JSON
with open(output_file, mode="w") as file:
    json.dump(inventory, file, indent=4)

print(f"Inventory matrix saved to {output_file}.")
