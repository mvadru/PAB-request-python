import sys
import os
import time
import requests
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QPushButton, QLabel, QMessageBox,
    QHeaderView
)
from PyQt6.QtCore import Qt
import json

# --- API Configuration (Unchanged) ---
SASE_API_BASE_URL = "https://api.sase.paloaltonetworks.com"
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
SECRETS_FILE = "secrets.txt"

# --- API Manager: Handles authentication and API calls (Unchanged) ---
class PanApiManager:
    """
    Manages the full authentication flow and API calls to the Palo Alto Networks SASE platform.
    """
    def __init__(self):
        self._secrets = self._load_secrets()
        self._access_token = None
        self._token_expiry_time = 0

    def _load_secrets(self):
        """Loads credentials from the secrets.txt file."""
        if not os.path.exists(SECRETS_FILE):
            return None
        secrets = {}
        try:
            with open(SECRETS_FILE, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        secrets[key] = value
            return secrets
        except Exception as e:
            print(f"Error reading secrets file: {e}")
            return None

    def _get_access_token(self):
        """Fetches a new access token using credentials from the secrets file."""
        if not self._secrets:
            return {'status': 'error', 'message': f"'{SECRETS_FILE}' not found or is invalid."}

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {
            'grant_type': 'client_credentials',
            'scope': f"tsg_id:{self._secrets.get('TSG_ID')}",
            'client_id': self._secrets.get('CLIENT_ID'),
            'client_secret': self._secrets.get('CLIENT_SECRET')
        }

        try:
            response = requests.post(AUTH_URL, headers=headers, data=payload)
            response.raise_for_status()
            token_data = response.json()
            self._access_token = token_data['access_token']
            self._token_expiry_time = time.time() + token_data['expires_in'] - 60
            return {'status': 'success'}
        except requests.exceptions.HTTPError as e:
            return {'status': 'error', 'message': f"Authentication Failed: {e.response.status_code} - {e.response.text}"}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'message': f"Connection Error during auth: {e}"}
        except KeyError:
             return {'status': 'error', 'message': "Invalid credentials in secrets.txt or incorrect API response."}

    def _get_valid_token(self):
        """Ensures a valid, non-expired token is available."""
        if not self._access_token or time.time() >= self._token_expiry_time:
            print("Access token is missing or expired. Fetching a new one...")
            auth_result = self._get_access_token()
            if auth_result['status'] == 'error':
                return auth_result
        return {'status': 'success', 'token': self._access_token}

    def _make_api_request(self, method, endpoint, params=None, json=None):
        """A generic helper to make authenticated API requests."""
        token_result = self._get_valid_token()
        if token_result['status'] == 'error':
            return token_result

        headers = {
            'Authorization': f'Bearer {token_result["token"]}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        url = f"{SASE_API_BASE_URL}{endpoint}"

        try:
            response = requests.request(method, url, headers=headers, params=params, json=json)
            response.raise_for_status()
            if method.upper() == 'GET':
                 return {'status': 'success', 'data': response.json()}
            else:
                 return {'status': 'success', 'message': 'Request successful.'}
        except requests.exceptions.HTTPError as e:
            return {'status': 'error', 'message': f"API Error: {e.response.status_code} - {e.response.text}"}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'message': f"Connection Error: {e}"}

    def get_pending_requests(self):
        """Fetches a list of pending user requests."""
        return self._make_api_request('GET', '/seb-api/v1/user-requests', params={'request.status': 'Pending'})

    def get_user_name(self,userid):
        """Fetches the user name by userid."""
        return self._make_api_request('GET', f'/seb-api/v1/users/{userid}', params=None)    

    def process_request(self, request_id, new_status, comment=""):
        """Approves or rejects a user request."""
        
        if new_status == 'reject':
            payload = {
                "action": "decline",
                "adminComment": comment
            }
        else:
            payload = {
                "action": "approve",
                "adminBypassTimeframe": "Once",
                "adminComment": comment
            }
        return self._make_api_request('POST', f'/seb-api/v1/user-requests/{request_id}/action', json=payload)

# --- Main GUI Application (Rewritten with PyQt6) ---
class RequestManagerApp(QMainWindow):
    def __init__(self, api_manager):
        super().__init__()
        self.api = api_manager
        self.setWindowTitle("Prisma Access Browser - Access Request Manager")
        self.setGeometry(100, 100, 850, 500)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self._create_widgets()
        self.refresh_requests()

    def _create_widgets(self):
        # Table for displaying requests
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Request ID", "Time", "User", "URL Requested", "Reason"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch) # Stretch URL column
        self.layout.addWidget(self.table)

        # Button layout
        button_layout = QHBoxLayout()
        self.refresh_button = QPushButton("🔄 Refresh")
        self.approve_button = QPushButton("✅ Approve")
        self.reject_button = QPushButton("❌ Decline")

        button_layout.addWidget(self.refresh_button)
        button_layout.addStretch()
        button_layout.addWidget(self.approve_button)
        button_layout.addWidget(self.reject_button)
        self.layout.addLayout(button_layout)

        # Status Bar
        self.status_label = QLabel("Ready.")
        self.sign = QLabel("by Marco Vadrucci - mvadrucci@paloaltonetworks.com")
        self.statusBar().addWidget(self.status_label)
        self.statusBar().addPermanentWidget(self.sign)

        # Connect signals to slots (event handlers)
        self.refresh_button.clicked.connect(self.refresh_requests)
        self.approve_button.clicked.connect(self.approve_selected)
        self.reject_button.clicked.connect(self.reject_selected)
        self.table.itemSelectionChanged.connect(self.update_action_buttons_state)
        
        self.update_action_buttons_state()

    def refresh_requests(self):
        self.status_label.setText("Fetching pending requests...")
        QApplication.processEvents() # Force UI update

        self.table.setRowCount(0) # Clear table
        response = self.api.get_pending_requests()

        if response['status'] == 'success':
            requests_data = response.get('data', {})
            requests_list = requests_data.get('data', [])
            if isinstance(requests_list, list):
                self.table.setRowCount(len(requests_list))
                for row, req in enumerate(requests_list):
                    user = req.get('userId')
                    name = self.api.get_user_name(user)
                    username = name['data']['name']
                    self.table.setItem(row, 0, QTableWidgetItem(req.get('id', 'N/A')))
                    self.table.setItem(row, 1, QTableWidgetItem(req.get('createdAt', 'N/A')))
                    self.table.setItem(row, 2, QTableWidgetItem(username))
                    self.table.setItem(row, 3, QTableWidgetItem(req.get('url', 'N/A')))
                    self.table.setItem(row, 4, QTableWidgetItem(req.get('reason', 'N/A')))
                self.status_label.setText(f"Loaded {len(requests_list)} pending requests.")
            else:
                QMessageBox.critical(self, "API Error", "Unexpected data format received from API.")
                self.status_label.setText("Error: Unexpected data format.")
        else:
            QMessageBox.critical(self, "API Error", f"Failed to fetch requests:\n{response.get('message')}")
            self.status_label.setText("Error fetching requests.")
        
        self.update_action_buttons_state()

    def update_action_buttons_state(self):
        """Enable or disable action buttons based on selection."""
        is_enabled = len(self.table.selectedItems()) > 0
        self.approve_button.setEnabled(is_enabled)
        self.reject_button.setEnabled(is_enabled)

    def get_selected_request_id(self):
        """Returns the ID of the selected request, or None."""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        # The ID is in the first column (index 0) of the selected row
        return self.table.item(selected_rows[0].row(), 0).text()

    def _process_action(self, action_name, status_to_set):
        request_id = self.get_selected_request_id()
        if not request_id:
            return

        reply = QMessageBox.question(self, f"Confirm {action_name}",
                                     f"Are you sure you want to {action_name.lower()} request {request_id}?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            self.status_label.setText(f"Processing {request_id}...")
            response = self.api.process_request(request_id, status_to_set, f"{action_name}d via API client")
            if response['status'] == 'success':
                QMessageBox.information(self, "Success", f"Request {request_id} {action_name.lower()}d successfully.")
            else:
                QMessageBox.critical(self, "Error", response['message'])
            self.refresh_requests()

    def approve_selected(self):
        self._process_action("Approve", "approve")

    def reject_selected(self):
        self._process_action("Reject", "reject")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    api_manager = PanApiManager()

    if not api_manager._secrets:
        QMessageBox.critical(None, "Configuration Error", f"'{SECRETS_FILE}' not found or is invalid.\nPlease create it with your TSG_ID, CLIENT_ID, and CLIENT_SECRET.")
        sys.exit(1)

    window = RequestManagerApp(api_manager)
    window.show()
    sys.exit(app.exec())
