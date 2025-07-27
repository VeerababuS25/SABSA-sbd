import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
import numpy as np
import json
import uuid
from datetime import datetime
import logging
import xml.etree.ElementTree as ET
from io import StringIO

# Configure logging for audit trail
logging.basicConfig(filename='sabsa_audit.log', level=logging.INFO, 
                    format='%(asctime)s - %(user)s - %(action)s - %(message)s')

# Page configuration for enterprise-grade application
st.set_page_config(
    page_title="Enterprise SABSA Security Architecture Framework",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise-grade CSS with professional styling
st.markdown("""
<style>
    :root {
        --primary-color: #1e3a8a;
        --secondary-color: #3b82f6;
        --accent-color: #60a5fa;
        --background-color: #f8fafc;
        --text-color: #1f2937;
        --border-color: #e5e7eb;
        --success-color: #059669;
        --error-color: #dc2626;
    }
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        background-color: var(--background-color);
        color: var(--text-color);
    }
    .main-header {
        font-size: 2.25rem;
        font-weight: 700;
        color: var(--primary-color);
        text-align: center;
        margin: 1.5rem 0;
        animation: fadeIn 0.8s ease-in;
    }
    .node-card {
        background-color: #ffffff;
        border: 1px solid var(--border-color);
        border-radius: 10px;
        padding: 12px;
        margin: 8px;
        text-align: center;
        font-size: 14px;
        font-weight: 500;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .node-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 6px 16px rgba(0,0,0,0.1);
    }
    .layer-header {
        background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        color: white;
        padding: 12px;
        border-radius: 8px;
        text-align: center;
        font-weight: 600;
        margin: 12px 0;
        animation: slideIn 0.5s ease-out;
    }
    .process-node {
        background-color: #f0f7ff;
        border: 2px solid var(--accent-color);
        border-radius: 50%;
        width: 100px;
        height: 100px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 12px;
        font-weight: 500;
        text-align: center;
        transition: transform 0.2s ease;
    }
    .process-node:hover {
        transform: scale(1.05);
    }
    .stButton>button {
        background: var(--primary-color);
        color: white;
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: 500;
        border: none;
        transition: background-color 0.2s ease;
    }
    .stButton>button:hover {
        background: var(--secondary-color);
    }
    .sidebar .stRadio > div {
        background: #ffffff;
        border-radius: 8px;
        padding: 8px;
        border: 1px solid var(--border-color);
    }
    .st-expander {
        background: #ffffff;
        border-radius: 8px;
        border: 1px solid var(--border-color);
    }
    .alert-success {
        color: var(--success-color);
        background-color: #ecfdf5;
        padding: 10px;
        border-radius: 8px;
        margin: 8px 0;
    }
    .alert-error {
        color: var(--error-color);
        background-color: #fef2f2;
        padding: 10px;
        border-radius: 8px;
        margin: 8px 0;
    }
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    @keyframes slideIn {
        from { transform: translateX(-20px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    .metric-card {
        background: #ffffff;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid var(--border-color);
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# Simulated user authentication and RBAC
if 'user' not in st.session_state:
    st.session_state.user = {"username": "guest", "role": "viewer"}  # Simulated; replace with enterprise SSO (e.g., Okta)
if 'version_history' not in st.session_state:
    st.session_state.version_history = []

# Initialize session state for framework data
if 'framework_data' not in st.session_state:
    st.session_state.framework_data = {
        "main_domains": {
            "Data Security": {"x": 1, "y": 5, "color": "#1e3a8a", "description": "Protects data assets", "risk_score": 0.8, "compliance": "ISO 27001"},
            "Identity & Access Management": {"x": 3, "y": 5, "color": "#1e3a8a", "description": "Controls access and identity", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Incident Handling & Response": {"x": 5, "y": 5, "color": "#1e3a8a", "description": "Manages security incidents", "risk_score": 0.9, "compliance": "ISO 27001"},
            "Vulnerability Management": {"x": 7, "y": 5, "color": "#1e3a8a", "description": "Handles vulnerabilities", "risk_score": 0.75, "compliance": "NIST 800-53"},
            "Security Risk Management": {"x": 9, "y": 5, "color": "#1e3a8a", "description": "Manages security risks", "risk_score": 0.85, "compliance": "ISO 27001"}
        },
        "secondary_nodes": {
            "Data Devaluation": {"x": 0.5, "y": 4, "color": "#3b82f6", "parent": "Data Security", "description": "Reduces data value exposure", "risk_score": 0.6, "compliance": "ISO 27001"},
            "Data Integrity": {"x": 1, "y": 4, "color": "#3b82f6", "parent": "Data Security", "description": "Ensures data accuracy", "risk_score": 0.65, "compliance": "ISO 27001"},
            "Data Confidentiality": {"x": 1.5, "y": 4, "color": "#3b82f6", "parent": "Data Security", "description": "Protects data privacy", "risk_score": 0.7, "compliance": "ISO 27001"},
            "Security Testing": {"x": 1, "y": 3, "color": "#3b82f6", "parent": "Data Security", "description": "Validates security controls", "risk_score": 0.55, "compliance": "NIST 800-53"},
            "Authentication": {"x": 2.5, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Verifies user identity", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Authorization": {"x": 3, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Controls access permissions", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Access Recertification": {"x": 3.5, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Reviews access rights", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Vulnerability Identification": {"x": 3, "y": 3, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Detects access vulnerabilities", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Remediation Management": {"x": 4.5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Manages incident fixes", "risk_score": 0.75, "compliance": "ISO 27001"},
            "Preparation": {"x": 5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Prepares for incidents", "risk_score": 0.8, "compliance": "ISO 27001"},
            "Recovery": {"x": 5.5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Restores normal operations", "risk_score": 0.7, "compliance": "ISO 27001"},
            "Incident Communication": {"x": 5, "y": 3, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Communicates incident details", "risk_score": 0.65, "compliance": "ISO 27001"},
            "Strategic Planning": {"x": 6.5, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management", "description": "Plans vulnerability strategy", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Change Management": {"x": 7, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management", "description": "Manages security changes", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Security Risk Integration": {"x": 7.5, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management", "description": "Integrates risk processes", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Governance & Reporting": {"x": 8.5, "y": 4, "color": "#3b82f6", "parent": "Security Risk Management", "description": "Manages governance", "risk_score": 0.75, "compliance": "ISO 27001"},
            "Security Services Management": {"x": 9, "y": 4, "color": "#3b82f6", "parent": "Security Risk Management", "description": "Oversees security services", "risk_score": 0.7, "compliance": "ISO 27001"}
        },
        "process_nodes": {
            "Encryption": {"x": 0.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Secures data with encryption", "risk_score": 0.5, "compliance": "ISO 27001"},
            "Masking": {"x": 1, "y": 2, "color": "#60a5fa", "type": "process", "description": "Obfuscates sensitive data", "risk_score": 0.5, "compliance": "ISO 27001"},
            "Anonymization": {"x": 1.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Removes identifiable data", "risk_score": 0.5, "compliance": "ISO 27001"},
            "Disclosure Authorization": {"x": 2, "y": 2, "color": "#60a5fa", "type": "process", "description": "Controls data disclosure", "risk_score": 0.55, "compliance": "ISO 27001"},
            "Validation": {"x": 2.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Validates security controls", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Digital Signing": {"x": 3, "y": 2, "color": "#60a5fa", "type": "process", "description": "Ensures data authenticity", "risk_score": 0.55, "compliance": "NIST 800-53"},
            "Multi-factor Authentication": {"x": 3.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Enhances authentication", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Vulnerability Analysis": {"x": 4, "y": 2, "color": "#60a5fa", "type": "process", "description": "Analyzes vulnerabilities", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Estimation of Extend": {"x": 4.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Estimates vulnerability impact", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Recovery Analysis": {"x": 5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Plans recovery strategies", "risk_score": 0.7, "compliance": "ISO 27001"},
            "Classification of Vulnerabilities": {"x": 5.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Categorizes vulnerabilities", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Events History Repository": {"x": 6, "y": 2, "color": "#60a5fa", "type": "process", "description": "Stores event history", "risk_score": 0.6, "compliance": "ISO 27001"},
            "Wargaming": {"x": 6.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Simulates attack scenarios", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Maturity Frameworks": {"x": 7, "y": 2, "color": "#60a5fa", "type": "process", "description": "Assesses maturity levels", "risk_score": 0.6, "compliance": "ISO 27001"},
            "Incident Response Planning": {"x": 7.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Plans incident response", "risk_score": 0.7, "compliance": "ISO 27001"},
            "Risk Appetite": {"x": 8, "y": 2, "color": "#60a5fa", "type": "process", "description": "Defines risk tolerance", "risk_score": 0.65, "compliance": "ISO 27001"},
            "Secure Repository": {"x": 0.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Secures data storage", "risk_score": 0.55, "compliance": "ISO 27001"},
            "Inventory of Basic Accounts": {"x": 1, "y": 1, "color": "#60a5fa", "type": "process", "description": "Tracks account inventory", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Control of Privileged Access": {"x": 1.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Manages privileged access", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Sandbox": {"x": 2, "y": 1, "color": "#60a5fa", "type": "process", "description": "Isolates testing environment", "risk_score": 0.55, "compliance": "NIST 800-53"},
            "Training": {"x": 2.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Educates staff", "risk_score": 0.5, "compliance": "ISO 27001"},
            "Role/Rule Management": {"x": 3, "y": 1, "color": "#60a5fa", "type": "process", "description": "Manages access roles", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Single Sign On": {"x": 3.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Simplifies authentication", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Remote Access Authentication": {"x": 4, "y": 1, "color": "#60a5fa", "type": "process", "description": "Secures remote access", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Monitoring and Qualification": {"x": 4.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Monitors security metrics", "risk_score": 0.6, "compliance": "ISO 27001"},
            "Business Alignment": {"x": 5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Aligns with business goals", "risk_score": 0.65, "compliance": "ISO 27001"},
            "Incident Escalation": {"x": 5.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Manages incident escalation", "risk_score": 0.7, "compliance": "ISO 27001"},
            "Change Management": {"x": 6, "y": 1, "color": "#60a5fa", "type": "process", "description": "Controls change processes", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Metrics, KPIs, KRIs and MI": {"x": 6.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Tracks performance metrics", "risk_score": 0.6, "compliance": "ISO 27001"},
            "Secure Transition": {"x": 7, "y": 1, "color": "#60a5fa", "type": "process", "description": "Ensures secure transitions", "risk_score": 0.65, "compliance": "ISO 27001"},
            "Strategy": {"x": 7.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Defines security strategy", "risk_score": 0.7, "compliance": "ISO 27001"},
            "Security Testing Framework": {"x": 0.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Structures security tests", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Penetration Testing": {"x": 1, "y": 0, "color": "#60a5fa", "type": "process", "description": "Simulates attacks", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Attestation": {"x": 1.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Certifies compliance", "risk_score": 0.6, "compliance": "ISO 27001"},
            "Automated Testing": {"x": 2, "y": 0, "color": "#60a5fa", "type": "process", "description": "Automates security tests", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Recertification": {"x": 2.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Renews certifications", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Authenticated Scanning": {"x": 3, "y": 0, "color": "#60a5fa", "type": "process", "description": "Scans with authentication", "risk_score": 0.65, "compliance": "NIST 800-53"},
            "Red Team Testing": {"x": 3.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Simulates advanced attacks", "risk_score": 0.7, "compliance": "NIST 800-53"},
            "Service Catalogue": {"x": 4, "y": 0, "color": "#60a5fa", "type": "process", "description": "Lists security services", "risk_score": 0.55, "compliance": "ISO 27001"},
            "Change Reconciliation": {"x": 4.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Reconciles changes", "risk_score": 0.6, "compliance": "NIST 800-53"},
            "Case Management": {"x": 5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Manages security cases", "risk_score": 0.65, "compliance": "ISO 27001"}
        },
        "connections": [
            ("Data Security", "Data Devaluation"),
            ("Data Security", "Data Integrity"),
            ("Data Security", "Data Confidentiality"),
            ("Data Security", "Security Testing"),
            ("Identity & Access Management", "Authentication"),
            ("Identity & Access Management", "Authorization"),
            ("Identity & Access Management", "Access Recertification"),
            ("Identity & Access Management", "Vulnerability Identification"),
            ("Incident Handling & Response", "Remediation Management"),
            ("Incident Handling & Response", "Preparation"),
            ("Incident Handling & Response", "Recovery"),
            ("Incident Handling & Response", "Incident Communication"),
            ("Vulnerability Management", "Strategic Planning"),
            ("Vulnerability Management", "Change Management"),
            ("Vulnerability Management", "Security Risk Integration"),
            ("Security Risk Management", "Governance & Reporting"),
            ("Security Risk Management", "Security Services Management"),
            ("Data Integrity", "Encryption"),
            ("Data Confidentiality", "Masking"),
            ("Authentication", "Multi-factor Authentication"),
            ("Authorization", "Role/Rule Management"),
            ("Preparation", "Incident Response Planning"),
            ("Recovery", "Business Alignment"),
            ("Strategic Planning", "Wargaming"),
            ("Change Management", "Change Management"),
            ("Security Services Management", "Metrics, KPIs, KRIs and MI")
        ]
    }

@st.cache_data
def get_framework_data():
    return st.session_state.framework_data

def log_action(action, message):
    """Log user actions for audit trail."""
    logging.info(f"user={st.session_state.user['username']}, action={action}, message={message}")

def validate_node_input(node_name, node_x, node_y, parent_node, node_type, existing_node=False):
    """Validate node input before adding or updating."""
    errors = []
    existing_nodes = {**st.session_state.framework_data["main_domains"], 
                     **st.session_state.framework_data["secondary_nodes"], 
                     **st.session_state.framework_data["process_nodes"]}
    if not node_name or len(node_name.strip()) == 0:
        errors.append("Node name cannot be empty.")
    if not existing_node and node_name in existing_nodes:
        errors.append("Node name must be unique.")
    if node_x < 0 or node_x > 10 or node_y < 0 or node_y > 5:
        errors.append("Position coordinates must be within bounds (X: 0-10, Y: 0-5).")
    if node_type == "Secondary Node" and parent_node == "None":
        errors.append("Secondary nodes must have a parent domain.")
    return errors

def save_version():
    """Save current framework state to version history."""
    version_id = str(uuid.uuid4())[:8]
    version_data = {
        "version_id": version_id,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "data": st.session_state.framework_data.copy(),
        "user": st.session_state.user["username"]
    }
    st.session_state.version_history.append(version_data)
    log_action("save_version", f"Saved version {version_id}")

def create_interactive_framework():
    st.markdown('<h1 class="main-header">🔒 Enterprise SABSA Security Architecture Framework</h1>', unsafe_allow_html=True)
    
    # Simulated RBAC check
    user_role = st.session_state.user["role"]
    is_admin = user_role in ["admin", "architect"]
    
    # Load data
    data = get_framework_data()
    main_domains = data["main_domains"]
    secondary_nodes = data["secondary_nodes"]
    process_nodes = data["process_nodes"]
    connections = data["connections"]
    
    # Professional control panel
    st.sidebar.title("Framework Controls")
    view_mode = st.sidebar.radio("Mode", ["View", "Management"] if is_admin else ["View"], key="view_mode")
    show_connections = st.sidebar.checkbox("Show Connections", value=True)
    show_labels = st.sidebar.checkbox("Show Labels", value=True)
    highlight_domain = st.sidebar.selectbox("Highlight Domain", ["None"] + list(main_domains.keys()))
    node_opacity = st.sidebar.slider("Node Opacity", 0.5, 1.0, 0.8, 0.05)
    show_risk_scores = st.sidebar.checkbox("Show Risk Scores", value=False)
    
    # Management mode (admin/architect only)
    if view_mode == "Management" and is_admin:
        with st.sidebar.expander("Add New Node", expanded=False):
            st.subheader("Create Node")
            node_type = st.selectbox("Node Type", ["Main Domain", "Secondary Node", "Process Node"], key="node_type")
            node_name = st.text_input("Node Name", key="node_name")
            node_description = st.text_area("Description (Optional)", height=100, key="node_desc")
            node_risk_score = st.number_input("Risk Score (0-1)", min_value=0.0, max_value=1.0, value=0.5, step=0.05, key="node_risk")
            node_compliance = st.selectbox("Compliance Standard", ["ISO 27001", "NIST 800-53", "GDPR", "Other"], key="node_compliance")
            node_x = st.number_input("X Position", min_value=0.0, max_value=10.0, value=1.0, step=0.1, key="node_x")
            node_y = st.number_input("Y Position", min_value=0.0, max_value=5.0, value=1.0, step=0.1, key="node_y")
            parent_node = st.selectbox("Parent Domain (for Secondary)", ["None"] + list(main_domains.keys()), key="node_parent") if node_type == "Secondary Node" else None
            connect_to = st.multiselect("Connect to Nodes", 
                                      list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()), key="node_connect")
            
            if st.button("Add Node", key="add_node"):
                errors = validate_node_input(node_name, node_x, node_y, parent_node, node_type)
                if errors:
                    for error in errors:
                        st.markdown(f'<div class="alert-error">{error}</div>', unsafe_allow_html=True)
                else:
                    save_version()
                    node_id = str(uuid.uuid4())[:8]
                    color = "#1e3a8a" if node_type == "Main Domain" else "#3b82f6" if node_type == "Secondary Node" else "#60a5fa"
                    
                    if node_type == "Main Domain":
                        main_domains[node_name] = {"x": node_x, "y": node_y, "color": color, "description": node_description, 
                                                  "risk_score": node_risk_score, "compliance": node_compliance}
                    elif node_type == "Secondary Node":
                        secondary_nodes[node_name] = {
                            "x": node_x, "y": node_y, "color": color, "parent": parent_node, 
                            "description": node_description, "risk_score": node_risk_score, "compliance": node_compliance
                        }
                    else:
                        process_nodes[node_name] = {
                            "x": node_x, "y": node_y, "color": color, "type": "process", 
                            "description": node_description, "risk_score": node_risk_score, "compliance": node_compliance
                        }
                    
                    for target in connect_to:
                        connections.append((node_name, target))
                    
                    st.session_state.framework_data = {
                        "main_domains": main_domains,
                        "secondary_nodes": secondary_nodes,
                        "process_nodes": process_nodes,
                        "connections": connections
                    }
                    st.markdown(f'<div class="alert-success">Node "{node_name}" added successfully</div>', unsafe_allow_html=True)
                    log_action("add_node", f"Added node: {node_name}")
        
        with st.sidebar.expander("Move Node", expanded=False):
            st.subheader("Reposition Node")
            node_to_move = st.selectbox("Select Node", 
                                      list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()), key="move_node")
            new_x = st.number_input("New X Position", min_value=0.0, max_value=10.0, value=1.0, step=0.1, key="move_x")
            new_y = st.number_input("New Y Position", min_value=0.0, max_value=5.0, value=1.0, step=0.1, key="move_y")
            
            if st.button("Move Node", key="move_node_btn"):
                if new_x < 0 or new_x > 10 or new_y < 0 or new_y > 5:
                    st.markdown('<div class="alert-error">Position coordinates must be within bounds (X: 0-10, Y: 0-5).</div>', unsafe_allow_html=True)
                else:
                    save_version()
                    if node_to_move in main_domains:
                        main_domains[node_to_move]["x"] = new_x
                        main_domains[node_to_move]["y"] = new_y
                    elif node_to_move in secondary_nodes:
                        secondary_nodes[node_to_move]["x"] = new_x
                        secondary_nodes[node_to_move]["y"] = new_y
                    elif node_to_move in process_nodes:
                        process_nodes[node_to_move]["x"] = new_x
                        process_nodes[node_to_move]["y"] = new_y
                    
                    st.session_state.framework_data = {
                        "main_domains": main_domains,
                        "secondary_nodes": secondary_nodes,
                        "process_nodes": process_nodes,
                        "connections": connections
                    }
                    st.markdown(f'<div class="alert-success">Node "{node_to_move}" moved to ({new_x}, {new_y})</div>', unsafe_allow_html=True)
                    log_action("move_node", f"Moved node {node_to_move} to ({new_x}, {new_y})")
        
        with st.sidebar.expander("Manage Connections", expanded=False):
            st.subheader("Add/Remove Connections")
            source_node = st.selectbox("Source Node", 
                                     list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()), key="source_node")
            target_node = st.selectbox("Target Node", 
                                     list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()), key="target_node")
            
            if st.button("Add Connection", key="add_connection"):
                if source_node == target_node:
                    st.markdown('<div class="alert-error">Source and target nodes cannot be the same.</div>', unsafe_allow_html=True)
                elif (source_node, target_node) in connections or (target_node, source_node) in connections:
                    st.markdown('<div class="alert-error">Connection already exists.</div>', unsafe_allow_html=True)
                else:
                    save_version()
                    connections.append((source_node, target_node))
                    st.session_state.framework_data["connections"] = connections
                    st.markdown(f'<div class="alert-success">Connection added: {source_node} → {target_node}</div>', unsafe_allow_html=True)
                    log_action("add_connection", f"Added connection: {source_node} → {target_node}")
            
            connection_to_remove = st.selectbox("Select Connection to Remove", 
                                              [f"{s} → {t}" for s, t in connections], key="remove_connection")
            if st.button("Remove Connection", key="remove_connection_btn"):
                if connection_to_remove:
                    save_version()
                    s, t = connection_to_remove.split(" → ")
                    connections.remove((s, t))
                    st.session_state.framework_data["connections"] = connections
                    st.markdown(f'<div class="alert-success">Connection removed: {s} → {t}</div>', unsafe_allow_html=True)
                    log_action("remove_connection", f"Removed connection: {s} → {t}")
        
        with st.sidebar.expander("Delete Node", expanded=False):
            st.subheader("Remove Node")
            node_to_delete = st.selectbox("Select Node to Delete", 
                                        list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()), key="delete_node")
            if st.button("Delete Node", key="delete_node_btn"):
                save_version()
                if node_to_delete in main_domains:
                    del main_domains[node_to_delete]
                    secondary_nodes_to_remove = [k for k, v in secondary_nodes.items() if v["parent"] == node_to_delete]
                    for node in secondary_nodes_to_remove:
                        del secondary_nodes[node]
                elif node_to_delete in secondary_nodes:
                    del secondary_nodes[node_to_delete]
                elif node_to_delete in process_nodes:
                    del process_nodes[node_to_delete]
                
                connections[:] = [c for c in connections if node_to_delete not in c]
                
                st.session_state.framework_data = {
                    "main_domains": main_domains,
                    "secondary_nodes": secondary_nodes,
                    "process_nodes": process_nodes,
                    "connections": connections
                }
                st.markdown(f'<div class="alert-success">Node "{node_to_delete}" deleted successfully</div>', unsafe_allow_html=True)
                log_action("delete_node", f"Deleted node: {node_to_delete}")
    
    # Create professional-grade visualization
    fig = go.Figure()
    
    # Add connections with smooth styling
    if show_connections:
        for connection in connections:
            start_node, end_node = connection
            start_coords = end_coords = None
            
            for node_set in [main_domains, secondary_nodes, process_nodes]:
                if start_node in node_set:
                    start_coords = (node_set[start_node]["x"], node_set[start_node]["y"])
                if end_node in node_set:
                    end_coords = (node_set[end_node]["x"], node_set[end_node]["y"])
            
            if start_coords and end_coords:
                fig.add_trace(go.Scatter(
                    x=[start_coords[0], end_coords[0]], 
                    y=[start_coords[1], end_coords[1]],
                    mode='lines',
                    line=dict(color='rgba(75,85,99,0.3)', width=2, shape='spline'),
                    showlegend=False,
                    hoverinfo='none'
                ))
    
    # Add main domain nodes
    main_x = [data["x"] for data in main_domains.values()]
    main_y = [data["y"] for data in main_domains.values()]
    main_names = list(main_domains.keys())
    main_colors = ['#dc2626' if name == highlight_domain else data["color"] for name, data in main_domains.items()]
    main_descriptions = [data.get("description", "") for data in main_domains.values()]
    main_risk_scores = [data.get("risk_score", 0) for data in main_domains.values()]
    main_compliance = [data.get("compliance", "") for data in main_domains.values()]
    
    fig.add_trace(go.Scatter(
        x=main_x, y=main_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=80,
            color=main_colors,
            line=dict(width=2, color='#ffffff'),
            symbol='square',
            opacity=node_opacity,
            colorscale='Reds' if show_risk_scores else None,
            showscale=show_risk_scores,
            cmin=0,
            cmax=1,
            color=main_risk_scores if show_risk_scores else main_colors
        ),
        text=main_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=12, color='#ffffff', family="Inter"),
        name="Main Domains",
        hovertemplate='<b>%{text}</b><br>Type: Main Domain<br>Description: %{customdata[0]}<br>Risk Score: %{customdata[1]:.2f}<br>Compliance: %{customdata[2]}<extra></extra>',
        customdata=list(zip(main_descriptions, main_risk_scores, main_compliance))
    ))
    
    # Add secondary nodes
    sec_x = [data["x"] for data in secondary_nodes.values()]
    sec_y = [data["y"] for data in secondary_nodes.values()]
    sec_names = list(secondary_nodes.keys())
    sec_colors = ['#f87171' if highlight_domain != "None" and secondary_nodes[name]["parent"] == highlight_domain 
                 else data["color"] for name, data in secondary_nodes.items()]
    sec_parents = [data["parent"] for data in secondary_nodes.values()]
    sec_descriptions = [data.get("description", "") for data in secondary_nodes.values()]
    sec_risk_scores = [data.get("risk_score", 0) for data in secondary_nodes.values()]
    sec_compliance = [data.get("compliance", "") for data in secondary_nodes.values()]
    
    fig.add_trace(go.Scatter(
        x=sec_x, y=sec_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=60,
            color=sec_colors,
            line=dict(width=1.5, color='#ffffff'),
            symbol='diamond',
            opacity=node_opacity,
            colorscale='Reds' if show_risk_scores else None,
            showscale=False,
            cmin=0,
            cmax=1,
            color=sec_risk_scores if show_risk_scores else sec_colors
        ),
        text=sec_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=10, family="Inter"),
        name="Secondary Nodes",
        hovertemplate='<b>%{text}</b><br>Type: Secondary<br>Parent: %{customdata[0]}<br>Description: %{customdata[1]}<br>Risk Score: %{customdata[2]:.2f}<br>Compliance: %{customdata[3]}<extra></extra>',
        customdata=list(zip(sec_parents, sec_descriptions, sec_risk_scores, sec_compliance))
    ))
    
    # Add process nodes
    proc_x = [data["x"] for data in process_nodes.values()]
    proc_y = [data["y"] for data in process_nodes.values()]
    proc_names = list(process_nodes.keys())
    proc_colors = [data["color"] for data in process_nodes.values()]
    proc_descriptions = [data.get("description", "") for data in process_nodes.values()]
    proc_risk_scores = [data.get("risk_score", 0) for data in process_nodes.values()]
    proc_compliance = [data.get("compliance", "") for data in process_nodes.values()]
    
    fig.add_trace(go.Scatter(
        x=proc_x, y=proc_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=40,
            color=proc_colors,
            line=dict(width=1.5, color='#4b5563'),
            symbol='circle',
            opacity=node_opacity,
            colorscale='Reds' if show_risk_scores else None,
            showscale=False,
            cmin=0,
            cmax=1,
            color=proc_risk_scores if show_risk_scores else proc_colors
        ),
        text=[name[:10] + '...' if len(name) > 10 else name for name in proc_names] if show_labels else None,
        textposition="middle center",
        textfont=dict(size=8, family="Inter"),
        name="Process Nodes",
        hovertemplate='<b>%{text}</b><br>Type: Process<br>Description: %{customdata[0]}<br>Risk Score: %{customdata[1]:.2f}<br>Compliance: %{customdata[2]}<extra></extra>',
        customdata=list(zip(proc_descriptions, proc_risk_scores, proc_compliance))
    ))
    
    # Professional layout
    fig.update_layout(
        title=dict(
            text="SABSA Security Architecture Framework",
            font=dict(size=24, color="#1e3a8a", family="Inter"),
            x=0.5,
            xanchor="center"
        ),
        xaxis=dict(
            showgrid=False,
            showticklabels=False,
            zeroline=False,
            range=[-0.5, 10.5]
        ),
        yaxis=dict(
            showgrid=False,
            showticklabels=False,
            zeroline=False,
            range=[-0.5, 5.5],
            scaleanchor="x",
            scaleratio=1
        ),
        plot_bgcolor='rgba(243,244,246,0.9)',
        paper_bgcolor='#ffffff',
        height=900,
        showlegend=True,
        legend=dict(
            x=0.01,
            y=0.99,
            bgcolor='rgba(255,255,255,0.9)',
            bordercolor='#1e3a8a',
            borderwidth=1,
            font=dict(family="Inter", size=12)
        ),
        dragmode='pan',
        hovermode='closest',
        margin=dict(l=30, r=30, t=80, b=30),
        font=dict(family="Inter")
    )
    
    # Display chart with advanced interactivity
    st.plotly_chart(fig, use_container_width=True, config={
        'displayModeBar': True,
        'modeBarButtonsToAdd': ['pan2d', 'zoomIn2d', 'zoomOut2d', 'resetScale2d', 'hoverClosest'],
        'scrollZoom': True,
        'displaylogo': False
    })
    
    return main_domains, secondary_nodes, process_nodes, connections

def show_detailed_view():
    st.header("Detailed Framework Analysis")
    
    main_domains, secondary_nodes, process_nodes, connections = create_interactive_framework()
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Domain Analysis",
        "🔗 Connection Matrix",
        "📋 Implementation Guide",
        "💾 Export Options",
        "📈 Risk Analytics"
    ])
    
    with tab1:
        st.subheader("Domain Analysis")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Main Domains", len(main_domains), delta_color="normal")
            st.markdown('</div>', unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Secondary Nodes", len(secondary_nodes), delta_color="normal")
            st.markdown('</div>', unsafe_allow_html=True)
        with col3:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Process Nodes", len(process_nodes), delta_color="normal")
            st.markdown('</div>', unsafe_allow_html=True)
        with col4:
            st.markdown('<div class="metric-card">', unsafe_allow_html=True)
            st.metric("Connections", len(connections), delta_color="normal")
            st.markdown('</div>', unsafe_allow_html=True)
        
        domain_data = []
        for domain, data in main_domains.items():
            secondary_count = sum(1 for node in secondary_nodes.values() if node["parent"] == domain)
            domain_data.append({
                "Domain": domain,
                "Type": "Main",
                "Secondary Nodes": secondary_count,
                "Connections": len([c for c in connections if domain in c]),
                "Description": data.get("description", ""),
                "Risk Score": data.get("risk_score", 0),
                "Compliance": data.get("compliance", "")
            })
        
        for node, data in secondary_nodes.items():
            domain_data.append({
                "Domain": node,
                "Type": "Secondary",
                "Secondary Nodes": 0,
                "Connections": len([c for c in connections if node in c]),
                "Description": data.get("description", ""),
                "Risk Score": data.get("risk_score", 0),
                "Compliance": data.get("compliance", "")
            })
        
        for node, data in process_nodes.items():
            domain_data.append({
                "Domain": node,
                "Type": "Process",
                "Secondary Nodes": 0,
                "Connections": len([c for c in connections if node in c]),
                "Description": data.get("description", ""),
                "Risk Score": data.get("risk_score", 0),
                "Compliance": data.get("compliance", "")
            })
        
        df = pd.DataFrame(domain_data)
        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "Domain": st.column_config.TextColumn("Domain Name", width="medium"),
                "Type": st.column_config.TextColumn("Type", width="small"),
                "Secondary Nodes": st.column_config.NumberColumn("Secondary Nodes", format="%d", width="small"),
                "Connections": st.column_config.NumberColumn("Connections", format="%d", width="small"),
                "Description": st.column_config.TextColumn("Description", width="large"),
                "Risk Score": st.column_config.NumberColumn("Risk Score", format="%.2f", width="small"),
                "Compliance": st.column_config.TextColumn("Compliance", width="medium")
            }
        )
    
    with tab2:
        st.subheader("Connection Matrix")
        
        all_nodes = list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys())
        matrix_size = len(all_nodes)
        matrix = np.zeros((matrix_size, matrix_size))
        
        for i, node1 in enumerate(all_nodes):
            for j, node2 in enumerate(all_nodes):
                if (node1, node2) in connections or (node2, node1) in connections:
                    matrix[i][j] = 1
        
        fig_matrix = go.Figure(data=go.Heatmap(
            z=matrix,
            x=all_nodes,
            y=all_nodes,
            colorscale='Blues',
            showscale=True,
            hovertemplate='Source: %{y}<br>Target: %{x}<br>Connected: %{z}<extra></extra>'
        ))
        
        fig_matrix.update_layout(
            title="Domain Connection Matrix",
            xaxis_title="Target Nodes",
            yaxis_title="Source Nodes",
            height=750,
            xaxis=dict(tickangle=45, tickfont=dict(family="Inter", size=12)),
            yaxis=dict(tickfont=dict(family="Inter", size=12)),
            margin=dict(l=120, r=120, t=100, b=100),
            font=dict(family="Inter")
        )
        
        st.plotly_chart(fig_matrix, use_container_width=True)
    
    with tab3:
        st.subheader("Implementation Guide")
        
        st.markdown("""
        ### Implementation Roadmap
        
        1. **Current State Assessment**  
           - Map existing controls to framework nodes  
           - Identify gaps using analytics dashboard  
           - Benchmark against industry standards (ISO 27001, NIST 800-53)
        
        2. **Implementation Prioritization**  
           - Deploy critical main domains first (based on risk scores)  
           - Focus on high-impact secondary nodes  
           - Automate process node deployment with CI/CD pipelines
        
        3. **Integration Strategy**  
           - Establish API-driven integrations with SIEM/GRC platforms  
           - Define data flows between nodes with metadata  
           - Implement real-time monitoring and alerting
        
        4. **Continuous Optimization**  
           - Conduct quarterly framework reviews with version control  
           - Update connections based on threat intelligence  
           - Leverage AI-driven insights for optimization
        """)
        
        st.subheader("Implementation Checklist")
        checklist_items = [
            "Identity & Access Management foundation established",
            "Data Security controls implemented",
            "Incident Response procedures defined",
            "Vulnerability Management program active",
            "Risk Management framework operational",
            "Process automation implemented",
            "Integration testing completed",
            "Staff training completed",
            "Documentation updated",
            "Monitoring and metrics established"
        ]
        
        for item in checklist_items:
            st.checkbox(item, key=f"check_{item}")
    
    with tab4:
        st.subheader("Export Options")
        
        if st.button("Export as JSON"):
            framework_export = {
                "main_domains": main_domains,
                "secondary_nodes": secondary_nodes,
                "process_nodes": process_nodes,
                "connections": connections,
                "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "version": "4.0",
                "user": st.session_state.user["username"]
            }
            
            st.json(framework_export)
            
            json_string = json.dumps(framework_export, indent=2)
            st.download_button(
                label="Download JSON",
                data=json_string,
                file_name="sabsa_framework.json",
                mime="application/json"
            )
            log_action("export_json", "Exported framework as JSON")
        
        if st.button("Export as CSV"):
            export_data = []
            
            for domain, data in main_domains.items():
                export_data.append({
                    "Node": domain,
                    "Type": "Main Domain",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": "",
                    "Connections": len([c for c in connections if domain in c]),
                    "Description": data.get("description", ""),
                    "Risk Score": data.get("risk_score", 0),
                    "Compliance": data.get("compliance", "")
                })
            
            for node, data in secondary_nodes.items():
                export_data.append({
                    "Node": node,
                    "Type": "Secondary",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": data["parent"],
                    "Connections": len([c for c in connections if node in c]),
                    "Description": data.get("description", ""),
                    "Risk Score": data.get("risk_score", 0),
                    "Compliance": data.get("compliance", "")
                })
            
            for node, data in process_nodes.items():
                export_data.append({
                    "Node": node,
                    "Type": "Process",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": "",
                    "Connections": len([c for c in connections if node in c]),
                    "Description": data.get("description", ""),
                    "Risk Score": data.get("risk_score", 0),
                    "Compliance": data.get("compliance", "")
                })
            
            export_df = pd.DataFrame(export_data)
            csv = export_df.to_csv(index=False)
            
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="sabsa_framework.csv",
                mime="text/csv"
            )
            log_action("export_csv", "Exported framework as CSV")
        
        if st.button("Export as XML"):
            root = ET.Element("SABSAFramework")
            root.set("version", "4.0")
            root.set("generated_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            root.set("user", st.session_state.user["username"])
            
            main_domains_elem = ET.SubElement(root, "MainDomains")
            for domain, data in main_domains.items():
                node = ET.SubElement(main_domains_elem, "Node")
                node.set("name", domain)
                node.set("x", str(data["x"]))
                node.set("y", str(data["y"]))
                node.set("color", data["color"])
                node.set("description", data.get("description", ""))
                node.set("risk_score", str(data.get("risk_score", 0)))
                node.set("compliance", data.get("compliance", ""))
            
            secondary_nodes_elem = ET.SubElement(root, "SecondaryNodes")
            for node, data in secondary_nodes.items():
                node_elem = ET.SubElement(secondary_nodes_elem, "Node")
                node_elem.set("name", node)
                node_elem.set("x", str(data["x"]))
                node_elem.set("y", str(data["y"]))
                node_elem.set("color", data["color"])
                node_elem.set("parent", data["parent"])
                node_elem.set("description", data.get("description", ""))
                node_elem.set("risk_score", str(data.get("risk_score", 0)))
                node_elem.set("compliance", data.get("compliance", ""))
            
            process_nodes_elem = ET.SubElement(root, "ProcessNodes")
            for node, data in process_nodes.items():
                node_elem = ET.SubElement(process_nodes_elem, "Node")
                node_elem.set("name", node)
                node_elem.set("x", str(data["x"]))
                node_elem.set("y", str(data["y"]))
                node_elem.set("color", data["color"])
                node_elem.set("type", data["type"])
                node_elem.set("description", data.get("description", ""))
                node_elem.set("risk_score", str(data.get("risk_score", 0)))
                node_elem.set("compliance", data.get("compliance", ""))
            
            connections_elem = ET.SubElement(root, "Connections")
            for source, target in connections:
                conn = ET.SubElement(connections_elem, "Connection")
                conn.set("source", source)
                conn.set("target", target)
            
            xml_string = ET.tostring(root, encoding='unicode')
            st.download_button(
                label="Download XML",
                data=xml_string,
                file_name="sabsa_framework.xml",
                mime="application/xml"
            )
            log_action("export_xml", "Exported framework as XML")
    
    with tab5:
        st.subheader("Risk Analytics")
        
        st.markdown("### Risk Score Distribution")
        risk_data = []
        for domain, data in main_domains.items():
            risk_data.append({"Node": domain, "Type": "Main Domain", "Risk Score": data.get("risk_score", 0)})
        for node, data in secondary_nodes.items():
            risk_data.append({"Node": node, "Type": "Secondary", "Risk Score": data.get("risk_score", 0)})
        for node, data in process_nodes.items():
            risk_data.append({"Node": node, "Type": "Process", "Risk Score": data.get("risk_score", 0)})
        
        risk_df = pd.DataFrame(risk_data)
        fig_risk = go.Figure()
        for node_type in risk_df["Type"].unique():
            type_df = risk_df[risk_df["Type"] == node_type]
            fig_risk.add_trace(go.Histogram(
                x=type_df["Risk Score"],
                name=node_type,
                opacity=0.6,
                nbinsx=20
            ))
        
        fig_risk.update_layout(
            title="Risk Score Distribution by Node Type",
            xaxis_title="Risk Score",
            yaxis_title="Count",
            barmode='overlay',
            height=500,
            font=dict(family="Inter")
        )
        
        st.plotly_chart(fig_risk, use_container_width=True)
        
        st.markdown("### AI-Driven Recommendations")
        high_risk_nodes = risk_df[risk_df["Risk Score"] >= 0.8]
        if not high_risk_nodes.empty:
            st.markdown("**High-Risk Nodes Detected:**")
            for _, row in high_risk_nodes.iterrows():
                st.markdown(f"- **{row['Node']}** ({row['Type']}): Risk Score {row['Risk Score']:.2f}. Recommended: Conduct immediate risk assessment and mitigation.")
        else:
            st.markdown("No high-risk nodes detected. Continue regular monitoring.")

def main():
    st.sidebar.title("SABSA Framework")
    st.sidebar.markdown(f"**User:** {st.session_state.user['username']} ({st.session_state.user['role']})")
    
    # Simulated authentication (replace with enterprise SSO)
    if st.session_state.user["role"] == "viewer":
        st.sidebar.markdown('<div class="alert-error">Viewer role: Management features restricted.</div>', unsafe_allow_html=True)
    
    view_mode = st.sidebar.radio(
        "Select View",
        ["Interactive Framework", "Detailed Analysis", "Version History", "About"],
        key="main_view_mode"
    )
    
    if view_mode == "Interactive Framework":
        create_interactive_framework()
    elif view_mode == "Detailed Analysis":
        show_detailed_view()
    elif view_mode == "Version History":
        st.header("Version History")
        if st.session_state.user["role"] in ["admin", "architect"]:
            if st.session_state.version_history:
                version_data = []
                for version in st.session_state.version_history:
                    version_data.append({
                        "Version ID": version["version_id"],
                        "Timestamp": version["timestamp"],
                        "User": version["user"],
                        "Nodes": len(version["data"]["main_domains"]) + len(version["data"]["secondary_nodes"]) + len(version["data"]["process_nodes"]),
                        "Connections": len(version["data"]["connections"])
                    })
                
                version_df = pd.DataFrame(version_data)
                st.dataframe(
                    version_df,
                    use_container_width=True,
                    column_config={
                        "Version ID": st.column_config.TextColumn("Version ID", width="medium"),
                        "Timestamp": st.column_config.TextColumn("Timestamp", width="medium"),
                        "User": st.column_config.TextColumn("User", width="medium"),
                        "Nodes": st.column_config.NumberColumn("Nodes", format="%d", width="small"),
                        "Connections": st.column_config.NumberColumn("Connections", format="%d", width="small")
                    }
                )
                
                selected_version = st.selectbox("Select Version to Restore", 
                                              [v["version_id"] for v in st.session_state.version_history])
                if st.button("Restore Version"):
                    for version in st.session_state.version_history:
                        if version["version_id"] == selected_version:
                            st.session_state.framework_data = version["data"].copy()
                            st.markdown(f'<div class="alert-success">Restored version {selected_version}</div>', unsafe_allow_html=True)
                            log_action("restore_version", f"Restored version {selected_version}")
                            break
            else:
                st.markdown("No version history available.")
        else:
            st.markdown('<div class="alert-error">Access restricted: Version history available to admins and architects only.</div>', unsafe_allow_html=True)
    elif view_mode == "About":
        st.header("About SABSA Framework")
        st.markdown("""
        The **Sherwood Applied Business Security Architecture (SABSA)** is an enterprise-grade methodology 
        for developing risk-driven security architectures aligned with business objectives.
        
        ### Enterprise Features:
        - **Secure Access**: Role-based access control with audit logging
        - **Advanced Visualization**: Interactive framework with risk score overlays
        - **Management Mode**: Add, move, delete nodes, and manage connections
        - **Version Control**: Track and restore framework versions
        - **Integration**: API-ready with JSON, CSV, and XML exports
        - **Analytics**: Risk score distribution and AI-driven recommendations
        
        ### Framework Structure:
        - **Main Domains**: Core security pillars
        - **Secondary Nodes**: Supporting capabilities
        - **Process Nodes**: Operational processes
        - **Connections**: Dynamic relationships
        
        This tool is designed for Fortune 100 enterprises, providing a secure, scalable platform for managing 
        the SABSA framework with compliance and risk management capabilities.
        """)

if __name__ == "__main__":
    main()
