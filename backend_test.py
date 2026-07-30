import requests
import sys
import json
from datetime import datetime

class CyberRangeAPITester:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)

            print(f"   Status: {response.status_code}")
            
            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - {name}")
                try:
                    response_data = response.json()
                    print(f"   Response keys: {list(response_data.keys()) if isinstance(response_data, dict) else 'Non-dict response'}")
                    return True, response_data
                except:
                    return True, response.text
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                self.failed_tests.append({
                    "test": name,
                    "expected": expected_status,
                    "actual": response.status_code,
                    "response": response.text[:200]
                })
                return False, {}

        except requests.exceptions.Timeout:
            print(f"❌ Failed - Timeout after {timeout}s")
            self.failed_tests.append({"test": name, "error": "Timeout"})
            return False, {}
        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            self.failed_tests.append({"test": name, "error": str(e)})
            return False, {}

    def test_root_endpoint(self):
        """Test API root endpoint"""
        return self.run_test("API Root", "GET", "", 200)

    def test_phishing_generation(self):
        """Test phishing email generation"""
        data = {
            "target_role": "Employee",
            "difficulty": "Medium", 
            "industry": "IT"
        }
        success, response = self.run_test(
            "Phishing Generation", 
            "POST", 
            "phishing/generate", 
            200, 
            data,
            timeout=60  # LLM calls can be slow
        )
        
        if success and isinstance(response, dict):
            required_fields = ['id', 'subject', 'body', 'red_flags', 'analysis']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"⚠️  Missing fields in response: {missing_fields}")
                return False
            print(f"   Generated email subject: {response.get('subject', 'N/A')[:50]}...")
            
        return success

    def test_ransomware_generation(self):
        """Test ransomware scenario generation"""
        data = {
            "attack_vector": "Email",
            "organization_type": "IT Company"
        }
        success, response = self.run_test(
            "Ransomware Generation", 
            "POST", 
            "ransomware/generate", 
            200, 
            data,
            timeout=60
        )
        
        if success and isinstance(response, dict):
            required_fields = ['id', 'attack_vector', 'infection_flow', 'mitre_mapping', 'prevention_tips']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"⚠️  Missing fields in response: {missing_fields}")
                return False
            print(f"   Generated {len(response.get('infection_flow', []))} infection steps")
            
        return success

    def test_attack_scenario_generation(self):
        """Test attack scenario generation"""
        data = {
            "organization_type": "Tech Startup",
            "security_maturity": "Medium"
        }
        success, response = self.run_test(
            "Attack Scenario Generation", 
            "POST", 
            "attack-scenario/generate", 
            200, 
            data,
            timeout=60
        )
        
        if success and isinstance(response, dict):
            required_fields = ['id', 'title', 'timeline']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"⚠️  Missing fields in response: {missing_fields}")
                return False
            print(f"   Generated scenario: {response.get('title', 'N/A')[:50]}...")
            
        return success

    def test_training_question_generation(self):
        """Test training question generation"""
        data = {
            "scenario_type": "Phishing"
        }
        success, response = self.run_test(
            "Training Question Generation", 
            "POST", 
            "training/question", 
            200, 
            data,
            timeout=60
        )
        
        if success and isinstance(response, dict):
            required_fields = ['id', 'question', 'options', 'correct_answer', 'explanation']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"⚠️  Missing fields in response: {missing_fields}")
                return False
            print(f"   Generated question with {len(response.get('options', []))} options")
            # Store question ID for answer test
            self.question_id = response.get('id')
            
        return success

    def test_training_answer_submission(self):
        """Test training answer submission"""
        if not hasattr(self, 'question_id'):
            print("⚠️  Skipping answer test - no question ID available")
            return False
            
        data = {
            "question_id": self.question_id,
            "user_answer": "B"
        }
        success, response = self.run_test(
            "Training Answer Submission", 
            "POST", 
            "training/answer", 
            200, 
            data
        )
        
        if success and isinstance(response, dict):
            required_fields = ['correct', 'explanation', 'score_gained']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"⚠️  Missing fields in response: {missing_fields}")
                return False
            print(f"   Answer result: {'Correct' if response.get('correct') else 'Incorrect'}")
            
        return success

    def test_dashboard_stats(self):
        """Test dashboard statistics"""
        success, response = self.run_test(
            "Dashboard Stats", 
            "GET", 
            "dashboard/stats", 
            200
        )
        
        if success and isinstance(response, dict):
            required_fields = ['total_simulations', 'phishing_sims', 'ransomware_sims', 'attack_scenarios', 'training_score']
            missing_fields = [field for field in required_fields if field not in response]
            if missing_fields:
                print(f"⚠️  Missing fields in response: {missing_fields}")
                return False
            print(f"   Stats: {response.get('total_simulations', 0)} total sims, {response.get('training_score', 0)} score")
            
        return success

def main():
    print("🚀 Starting CyberRange AI Backend Testing...")
    print("=" * 60)
    
    tester = CyberRangeAPITester()
    
    # Test all endpoints
    tests = [
        tester.test_root_endpoint,
        tester.test_dashboard_stats,
        tester.test_phishing_generation,
        tester.test_ransomware_generation,
        tester.test_attack_scenario_generation,
        tester.test_training_question_generation,
        tester.test_training_answer_submission,
    ]
    
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"❌ Test failed with exception: {str(e)}")
            tester.failed_tests.append({"test": test.__name__, "error": str(e)})
    
    # Print summary
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {tester.tests_passed}/{tester.tests_run} passed")
    
    if tester.failed_tests:
        print("\n❌ Failed Tests:")
        for failure in tester.failed_tests:
            print(f"   - {failure['test']}: {failure.get('error', 'Status code mismatch')}")
    
    success_rate = (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0
    print(f"\n🎯 Success Rate: {success_rate:.1f}%")
    
    return 0 if tester.tests_passed == tester.tests_run else 1

if __name__ == "__main__":
    sys.exit(main())
