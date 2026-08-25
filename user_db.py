import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

class UserDB:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.users: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self):
        if self.db_path.exists():
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    self.users = json.load(f)
            except Exception:
                self.users = {}
        else:
            self.users = {}

    def save(self):
        with open(self.db_path, "w", encoding="utf-8") as f:
            json.dump(self.users, f, indent=4)

    def get_user(self, user_id: str) -> Dict[str, Any]:
        user_id = str(user_id)
        if user_id not in self.users:
            self.users[user_id] = {
                "plan": "FREE",
                "usage": 0,
                "last_free_date": ""
            }
            self.save()
        return self.users[user_id]

    def set_plan(self, user_id: str, plan: str):
        user_id = str(user_id)
        user = self.get_user(user_id)
        user["plan"] = plan.upper()
        self.save()

    def check_and_add_usage(self, user_id: str, amount: int = 1) -> tuple[bool, str]:
        user_id = str(user_id)
        user = self.get_user(user_id)
        plan = user.get("plan", "FREE")
        
        if plan == "VIP":
            return True, ""
            
        if plan == "FREE":
            today = datetime.now().strftime("%Y-%m-%d")
            if user.get("last_free_date") == today:
                return False, "FREE plan limit reached. You can only use the bot once per day. Upgrade to BASIC or VIP."
            user["last_free_date"] = today
            self.save()
            return True, ""
            
        if plan == "BASIC":
            current_usage = user.get("usage", 0)
            if current_usage + amount > 25000:
                return False, f"BASIC plan limit reached (25k max). You have used {current_usage}. Please upgrade to VIP."
            user["usage"] = current_usage + amount
            self.save()
            return True, ""

        return False, "Unknown plan."
