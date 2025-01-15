import unittest
from ParseSMBLogs import parse_logs  # Assuming parse_logs is the main function in ParseSMBLogs.py

class TestParseSMBLogs(unittest.TestCase):
    def setUp(self):
        self.mock_data = [
            {"Endpoint": "Endpoint-1.domain.com", "EnableSMB1Protocol": "True", "EnableSMB2Protocol": "False", "EnableSMB3Protocol": "True"},
            {"Endpoint": "Endpoint-2.domain.com", "EnableSMB1Protocol": "False", "EnableSMB2Protocol": "True", "EnableSMB3Protocol": "False"},
            {"Endpoint": "Endpoint-3.domain.com", "EnableSMB1Protocol": "False", "EnableSMB2Protocol": "False", "EnableSMB3Protocol": "True"},
        ]

    def test_risk_level_assignment(self):
        parsed_data = parse_logs(self.mock_data)
        self.assertEqual(parsed_data[0]['RiskLevel'], 'High')
        self.assertEqual(parsed_data[1]['RiskLevel'], 'Medium')
        self.assertEqual(parsed_data[2]['RiskLevel'], 'Low')

    def test_output_format(self):
        parsed_data = parse_logs(self.mock_data)
        self.assertTrue(all('RiskLevel' in entry for entry in parsed_data))

if __name__ == "__main__":
    unittest.main()
