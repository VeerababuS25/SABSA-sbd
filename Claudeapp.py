import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np
import json
import datetime
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional
import sqlite3
import hashlib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

# Enterprise Configuration
ENTERPRISE_CONFIG = {
    "company_name": "Fortune 100 Corp",
    "classification_levels": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
    "risk_appetite_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "compliance_frameworks": ["SOX", "PCI-DSS", "GDPR", "HIPAA", "ISO27001", "NIST", "SOC2"],
    "business_units": ["Finance", "HR", "IT", "Operations", "Legal", "Marketing", "R&D"],
    "geographic_regions": ["Americas", "EMEA", "APAC"]
}

# Data Models for Enterprise Features
@dataclass
class SecurityControl:
    control_id: str
    name: str
    description: str
    framework: str
    implementation_status: str
    risk_level: str
    owner: str
    last_assessment: datetime.date
    next_review: datetime.date
    cost: float
    effectiveness_score: float

@dataclass
class RiskAssessment:
    risk_id: str
    domain: str
    description: str
    likelihood: int
    impact: int
    risk_score: int
    mitigation_controls: List[str]
    owner: str
    status: str
    target_date: datetime.date

@dataclass
class ComplianceMapping:
    framework: str
    requirement: str
    sabsa_domain: str
    control_id: str
    compliance_status: str
    evidence: str
    auditor_notes: str

# Page configuration with enterprise theming
st.set_page_config(
    page_title="Enterprise Security Architecture Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise CSS with professional styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1a365d;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: 700;
    }
    .executive-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 20px;
        border-radius: 12px;
        margin: 10px 0;
        box-shadow: 0 8px 16px rgba(0,0,0,0.1);
    }
    .risk-critical { background-color: #fee2e2; border-left: 4px solid #dc2626; }
    .risk-high { background-color: #fef3c7; border-left: 4px solid #f59e0b; }
    .risk-medium { background-color: #dbeafe; border-left: 4px solid #3b82f6; }
    .risk-low { background-color: #d1fae5; border-left: 4px solid #10b981; }
    .compliance-compliant { color: #10b981; font-weight: bold; }
    .compliance-non-compliant { color: #dc2626; font-weight: bold; }
    .compliance-partial { color: #f59e0b; font-weight: bold; }
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        border-left: 4px solid #3b82f6;
        margin: 10px 0;
    }
    .alert-banner {
        background-color: #fef2f2;
        border: 1px solid #fecaca;
        color: #991b1b;
        padding: 12px;
        border-radius: 8px;
        margin: 10px 0;
    }
    .sidebar .sidebar-content {
        background-color: #f8fafc;
    }
</style>
""", unsafe_allow_html=True)

# Enterprise Authentication and RBAC
class EnterpriseAuth:
    def __init__(self):
        self.roles = {
            "CISO": ["read", "write", "admin", "approve"],
            "Security_Architect": ["read", "write", "design"],
            "Security_Manager": ["read", "write", "manage"],
            "Security_Analyst": ["read", "analyze"],
            "Auditor": ["read", "audit"],
            "Executive": ["read", "executive"]
        }
    
    def authenticate_user(self, username: str, role: str) -> bool:
        # In production, integrate with enterprise SSO/LDAP
        if not hasattr(st.session_state, 'authenticated'):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.username = None
        
        return st.session_state.authenticated
    
    def check_permission(self, required_permission: str) -> bool:
        if not st.session_state.authenticated:
            return False
        user_permissions = self.roles.get(st.session_state.user_role, [])
        return required_permission in user_permissions

# Enterprise Data Management
class EnterpriseDataManager:
    def __init__(self):
        self.init_database()
    
    def init_database(self):
        # In production, use enterprise database (PostgreSQL, Oracle, etc.)
        conn = sqlite3.connect('enterprise_security.db')
        cursor = conn.cursor()
        
        # Create tables for enterprise data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_controls (
                control_id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                framework TEXT,
                implementation_status TEXT,
                risk_level TEXT,
                owner TEXT,
                last_assessment DATE,
                next_review DATE,
                cost REAL,
                effectiveness_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_assessments (
                risk_id TEXT PRIMARY KEY,
                domain TEXT,
                description TEXT,
                likelihood INTEGER,
                impact INTEGER,
                risk_score INTEGER,
                mitigation_controls TEXT,
                owner TEXT,
                status TEXT,
                target_date DATE,
                created_date DATE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_mappings (
                id TEXT PRIMARY KEY,
                framework TEXT,
                requirement TEXT,
                sabsa_domain TEXT,
                control_id TEXT,
                compliance_status TEXT,
                evidence TEXT,
                auditor_notes TEXT,
                last_review DATE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_security_controls(self) -> List[SecurityControl]:
        conn = sqlite3.connect('enterprise_security.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM security_controls')
        rows = cursor.fetchall()
        conn.close()
        
        controls = []
        for row in rows:
            controls.append(SecurityControl(
                control_id=row[0], name=row[1], description=row[2],
                framework=row[3], implementation_status=row[4],
                risk_level=row[5], owner=row[6],
                last_assessment=datetime.datetime.strptime(row[7], '%Y-%m-%d').date() if row[7] else None,
                next_review=datetime.datetime.strptime(row[8], '%Y-%m-%d').date() if row[8] else None,
                cost=row[9], effectiveness_score=row[10]
            ))
        return controls

# Enterprise Risk Engine
class EnterpriseRiskEngine:
    def __init__(self):
        self.risk_matrix = {
            (1, 1): ("LOW", "#10b981"), (1, 2): ("LOW", "#10b981"), (1, 3): ("MEDIUM", "#3b82f6"),
            (2, 1): ("LOW", "#10b981"), (2, 2): ("MEDIUM", "#3b82f6"), (2, 3): ("HIGH", "#f59e0b"),
            (3, 1): ("MEDIUM", "#3b82f6"), (3, 2): ("HIGH", "#f59e0b"), (3, 3): ("CRITICAL", "#dc2626")
        }
    
    def calculate_risk_score(self, likelihood: int, impact: int) -> tuple:
        score = likelihood * impact
        risk_level, color = self.risk_matrix.get((likelihood, impact), ("UNKNOWN", "#6b7280"))
        return score, risk_level, color
    
    def generate_risk_heatmap(self, risks: List[RiskAssessment]):
        # Create risk heatmap for executive dashboard
        likelihood_vals = [r.likelihood for r in risks]
        impact_vals = [r.impact for r in risks]
        
        fig = go.Figure()
        
        # Add risk points
        fig.add_trace(go.Scatter(
            x=likelihood_vals,
            y=impact_vals,
            mode='markers+text',
            marker=dict(
                size=[r.risk_score * 5 for r in risks],
                color=[r.risk_score for r in risks],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Risk Score")
            ),
            text=[r.domain for r in risks],
            textposition="top center",
            hovertemplate='<b>%{text}</b><br>Likelihood: %{x}<br>Impact: %{y}<br>Score: %{marker.color}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Enterprise Risk Heatmap",
            xaxis_title="Likelihood",
            yaxis_title="Impact",
            xaxis=dict(range=[0.5, 3.5], dtick=1),
            yaxis=dict(range=[0.5, 3.5], dtick=1),
            height=500
        )
        
        return fig

# Integration with Enterprise Systems
class EnterpriseIntegrations:
    def __init__(self):
        self.integrations = {
            "ServiceNow": {"status": "Connected", "last_sync": "2024-01-15 09:30"},
            "Splunk": {"status": "Connected", "last_sync": "2024-01-15 09:25"},
            "CyberArk": {"status": "Connected", "last_sync": "2024-01-15 09:20"},
            "Qualys": {"status": "Connected", "last_sync": "2024-01-15 09:15"},
            "Archer GRC": {"status": "Connected", "last_sync": "2024-01-15 09:10"},
            "Microsoft Sentinel": {"status": "Connected", "last_sync": "2024-01-15 09:05"},
            "Okta": {"status": "Connected", "last_sync": "2024-01-15 09:00"}
        }
    
    def sync_with_servicenow(self):
        # Mock ServiceNow integration
        return {"incidents": 45, "changes": 12, "problems": 3}
    
    def sync_with_splunk(self):
        # Mock Splunk integration
        return {"alerts": 234, "events": 1500000, "threats": 12}
    
    def sync_with_grc_platform(self):
        # Mock GRC platform integration
        return {"open_findings": 67, "overdue_reviews": 8, "compliance_score": 94.2}

# Executive Dashboard
def create_executive_dashboard():
    st.markdown('<h1 class="main-header">🛡️ Executive Security Dashboard</h1>', unsafe_allow_html=True)
    
    # Check executive permissions
    auth = EnterpriseAuth()
    if not auth.check_permission("executive"):
        st.error("Access Denied: Executive privileges required")
        return
    
    # Key Security Metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Security Posture Score", "87.3%", "↑ 2.1%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Critical Risks", "3", "↓ 2")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Compliance Score", "94.2%", "↑ 1.8%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        st.markdown('<div class="executive-card">', unsafe_allow_html=True)
        st.metric("Security Budget Utilization", "78.5%", "↑ 5.2%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Risk and Compliance Overview
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Top Security Risks")
        risks_data = [
            {"Risk": "Third-party Data Breach", "Score": 9, "Owner": "J. Smith", "Due": "2024-02-15"},
            {"Risk": "Insider Threat", "Score": 8, "Owner": "M. Johnson", "Due": "2024-02-20"},
            {"Risk": "Ransomware Attack", "Score": 8, "Owner": "A. Davis", "Due": "2024-02-25"},
            {"Risk": "Cloud Misconfiguration", "Score": 7, "Owner": "R. Wilson", "Due": "2024-03-01"},
            {"Risk": "Supply Chain Attack", "Score": 7, "Owner": "L. Brown", "Due": "2024-03-05"}
        ]
        
        for risk in risks_data:
            risk_class = "risk-critical" if risk["Score"] >= 9 else "risk-high" if risk["Score"] >= 7 else "risk-medium"
            st.markdown(f'''
            <div class="{risk_class}" style="padding: 10px; margin: 5px 0; border-radius: 5px;">
                <strong>{risk["Risk"]}</strong> (Score: {risk["Score"]})<br>
                Owner: {risk["Owner"]} | Due: {risk["Due"]}
            </div>
            ''', unsafe_allow_html=True)
    
    with col2:
        st.subheader("Compliance Status by Framework")
        compliance_data = [
            {"Framework": "SOX", "Status": "Compliant", "Score": 98.5},
            {"Framework": "PCI-DSS", "Status": "Compliant", "Score": 96.2},
            {"Framework": "GDPR", "Status": "Partial", "Score": 89.7},
            {"Framework": "ISO27001", "Status": "Compliant", "Score": 94.8},
            {"Framework": "NIST", "Status": "Partial", "Score": 87.3}
        ]
        
        for comp in compliance_data:
            status_class = "compliance-compliant" if comp["Status"] == "Compliant" else "compliance-partial"
            st.markdown(f'''
            <div class="metric-card">
                <strong>{comp["Framework"]}</strong><br>
                <span class="{status_class}">{comp["Status"]}</span> - {comp["Score"]}%
            </div>
            ''', unsafe_allow_html=True)
    
    # Budget and ROI Analysis
    st.subheader("Security Investment Analysis")
    
    budget_data = {
        'Category': ['Personnel', 'Technology', 'Training', 'Consulting', 'Compliance'],
        'Allocated': [12.5, 8.3, 1.2, 2.1, 1.5],
        'Spent': [11.8, 7.9, 1.0, 1.9, 1.3],
        'ROI_Score': [85, 92, 78, 88, 91]
    }
    
    fig = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Budget Allocation vs Spending ($M)', 'Security ROI by Category'),
        specs=[[{"secondary_y": False}, {"secondary_y": False}]]
    )
    
    fig.add_trace(
        go.Bar(name='Allocated', x=budget_data['Category'], y=budget_data['Allocated']),
        row=1, col=1
    )
    fig.add_trace(
        go.Bar(name='Spent', x=budget_data['Category'], y=budget_data['Spent']),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(x=budget_data['Category'], y=budget_data['ROI_Score'], 
                  mode='lines+markers', name='ROI Score'),
        row=1, col=2
    )
    
    fig.update_layout(height=400, showlegend=True)
    st.plotly_chart(fig, use_container_width=True)

# Advanced Risk Management
def create_risk_management_module():
    st.header("🎯 Enterprise Risk Management")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("manage"):
        st.error("Access Denied: Management privileges required")
        return
    
    tabs = st.tabs(["Risk Register", "Risk Analysis", "Mitigation Planning", "Risk Reporting"])
    
    with tabs[0]:
        st.subheader("Enterprise Risk Register")
        
        # Risk entry form
        with st.expander("Add New Risk"):
            col1, col2 = st.columns(2)
            with col1:
                risk_domain = st.selectbox("Domain", ["Data Security", "Identity & Access Management", 
                                                    "Incident Response", "Vulnerability Management", 
                                                    "Security Risk Management"])
                risk_description = st.text_area("Risk Description")
                likelihood = st.selectbox("Likelihood", [1, 2, 3], format_func=lambda x: ["Low", "Medium", "High"][x-1])
            
            with col2:
                impact = st.selectbox("Impact", [1, 2, 3], format_func=lambda x: ["Low", "Medium", "High"][x-1])
                risk_owner = st.selectbox("Risk Owner", ["CISO", "Security Manager", "IT Director", "Business Owner"])
                target_date = st.date_input("Target Mitigation Date")
            
            if st.button("Add Risk"):
                risk_engine = EnterpriseRiskEngine()
                score, level, color = risk_engine.calculate_risk_score(likelihood, impact)
                st.success(f"Risk added with score: {score} ({level})")
        
        # Risk register table
        sample_risks = [
            {"ID": "RSK-001", "Domain": "Data Security", "Description": "Data breach via third-party", 
             "Likelihood": 2, "Impact": 3, "Score": 6, "Level": "HIGH", "Owner": "CISO", "Status": "Open"},
            {"ID": "RSK-002", "Domain": "Identity & Access Management", "Description": "Privileged account compromise", 
             "Likelihood": 1, "Impact": 3, "Score": 3, "Level": "MEDIUM", "Owner": "Security Manager", "Status": "Mitigating"},
            {"ID": "RSK-003", "Domain": "Incident Response", "Description": "Delayed incident response", 
             "Likelihood": 2, "Impact": 2, "Score": 4, "Level": "MEDIUM", "Owner": "IR Manager", "Status": "Open"}
        ]
        
        df_risks = pd.DataFrame(sample_risks)
        st.dataframe(df_risks, use_container_width=True)
    
    with tabs[1]:
        st.subheader("Risk Analysis & Heat Map")
        
        # Generate sample data for risk analysis
        risk_engine = EnterpriseRiskEngine()
        sample_risk_objects = [
            RiskAssessment("RSK-001", "Data Security", "Data breach", 2, 3, 6, ["CTRL-001"], "CISO", "Open", datetime.date.today()),
            RiskAssessment("RSK-002", "Identity Management", "Account compromise", 1, 3, 3, ["CTRL-002"], "Sec Mgr", "Mitigating", datetime.date.today()),
            RiskAssessment("RSK-003", "Incident Response", "Response delay", 2, 2, 4, ["CTRL-003"], "IR Mgr", "Open", datetime.date.today())
        ]
        
        heatmap = risk_engine.generate_risk_heatmap(sample_risk_objects)
        st.plotly_chart(heatmap, use_container_width=True)
        
        # Risk trend analysis
        st.subheader("Risk Trend Analysis")
        dates = pd.date_range(start='2023-01-01', end='2024-01-01', freq='M')
        risk_counts = np.random.randint(10, 50, len(dates))
        
        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(x=dates, y=risk_counts, mode='lines+markers', name='Risk Count'))
        fig_trend.update_layout(title="Risk Count Trend Over Time", xaxis_title="Date", yaxis_title="Number of Risks")
        st.plotly_chart(fig_trend, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Risk Mitigation Planning")
        
        # Mitigation strategy matrix
        mitigation_strategies = {
            "Accept": {"Cost": "Low", "Time": "Immediate", "Effectiveness": "Low"},
            "Avoid": {"Cost": "High", "Time": "Long", "Effectiveness": "High"},
            "Mitigate": {"Cost": "Medium", "Time": "Medium", "Effectiveness": "Medium"},
            "Transfer": {"Cost": "Medium", "Time": "Short", "Effectiveness": "Medium"}
        }
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Mitigation Strategies")
            for strategy, details in mitigation_strategies.items():
                st.write(f"**{strategy}**: Cost: {details['Cost']}, Time: {details['Time']}, Effectiveness: {details['Effectiveness']}")
        
        with col2:
            st.subheader("Control Effectiveness Analysis")
            control_data = {
                'Control': ['Data Encryption', 'MFA', 'SIEM', 'DLP', 'PAM'],
                'Effectiveness': [95, 92, 88, 85, 90],
                'Cost': [100, 50, 200, 150, 120]
            }
            
            fig_controls = go.Figure()
            fig_controls.add_trace(go.Scatter(
                x=control_data['Cost'], 
                y=control_data['Effectiveness'],
                mode='markers+text',
                text=control_data['Control'],
                textposition="top center",
                marker=dict(size=15, color='blue')
            ))
            fig_controls.update_layout(
                title="Control Cost vs Effectiveness",
                xaxis_title="Cost ($K)",
                yaxis_title="Effectiveness (%)"
            )
            st.plotly_chart(fig_controls, use_container_width=True)
    
    with tabs[3]:
        st.subheader("Executive Risk Reporting")
        
        # Generate executive risk report
        if st.button("Generate Executive Risk Report"):
            st.markdown("""
            ## Executive Risk Summary
            
            ### Key Findings:
            - **3 Critical Risks** requiring immediate attention
            - **12 High Risks** with mitigation plans in progress
            - **Risk posture improved 15%** over last quarter
            
            ### Top Recommendations:
            1. Accelerate third-party risk assessment program
            2. Increase investment in identity management controls
            3. Enhance incident response capabilities
            
            ### Budget Impact:
            - Additional $2.3M required for critical risk mitigation
            - Expected ROI: 300% over 2 years
            - Regulatory compliance maintained at 94%
            """)

# Compliance Management
def create_compliance_module():
    st.header("📋 Compliance Management")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("audit"):
        st.error("Access Denied: Audit privileges required")
        return
    
    tabs = st.tabs(["Framework Mapping", "Control Assessment", "Audit Management", "Compliance Reporting"])
    
    with tabs[0]:
        st.subheader("Regulatory Framework Mapping")
        
        # Framework selection
        selected_framework = st.selectbox("Select Compliance Framework", 
                                        ENTERPRISE_CONFIG["compliance_frameworks"])
        
        # Sample compliance mapping
        compliance_mappings = {
            "SOX": [
                {"Requirement": "ITGC-001", "SABSA Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
                {"Requirement": "ITGC-002", "SABSA Domain": "Identity & Access Management", "Control": "Access Reviews", "Status": "Compliant"},
                {"Requirement": "ITGC-003", "SABSA Domain": "Incident Response", "Control": "Change Management", "Status": "Partial"}
            ],
            "PCI-DSS": [
                {"Requirement": "PCI-3.4", "SABSA Domain": "Data Security", "Control": "Data Encryption", "Status": "Compliant"},
                {"Requirement": "PCI-8.1", "SABSA Domain": "Identity & Access Management", "Control": "User Authentication", "Status": "Compliant"},
                {"Requirement": "PCI-11.1", "SABSA Domain": "Vulnerability Management", "Control": "Vulnerability Scanning", "Status": "Compliant"}
            ]
        }
        
        if selected_framework in compliance_mappings:
            df_compliance = pd.DataFrame(compliance_mappings[selected_framework])
            st.dataframe(df_compliance, use_container_width=True)
    
    with tabs[1]:
        st.subheader("Control Assessment")
        
        # Control assessment form
        col1, col2 = st.columns(2)
        
        with col1:
            control_id = st.text_input("Control ID")
            control_name = st.text_input("Control Name")
            assessment_date = st.date_input("Assessment Date")
        
        with col2:
            effectiveness = st.selectbox("Control Effectiveness", ["Ineffective", "Partially Effective", "Effective"])
            test_result = st.selectbox("Test Result", ["Pass", "Fail", "Exception"])
            next_review = st.date_input("Next Review Date")
        
        if st.button("Submit Assessment"):
            st.success("Control assessment submitted successfully")
        
        # Assessment results summary
        st.subheader("Assessment Results Summary")
        assessment_data = {
            'Control Category': ['Access Control', 'Data Protection', 'Monitoring', 'Incident Response', 'Risk Management'],
            'Total Controls': [25, 18, 15, 12, 20],
            'Effective': [23, 17, 14, 11, 18],
            'Partially Effective': [2, 1, 1, 1, 2],
            'Ineffective': [0, 0, 0, 0, 0]
        }
        
        df_assessment = pd.DataFrame(assessment_data)
        st.dataframe(df_assessment, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Audit Management")
        
        # Upcoming audits
        upcoming_audits = [
            {"Audit": "SOX ITGC Assessment", "Auditor": "KPMG", "Start Date": "2024-02-15", "Status": "Scheduled"},
            {"Audit": "PCI-DSS Assessment", "Auditor": "Internal", "Start Date": "2024-03-01", "Status": "Preparing"},
            {"Audit": "ISO27001 Certification", "Auditor": "BSI", "Start Date": "2024-04-01", "Status": "Planning"}
        ]
        
        df_audits = pd.DataFrame(upcoming_audits)
        st.dataframe(df_audits, use_container_width=True)
        
        # Audit findings tracking
        st.subheader("Audit Findings Status")
        findings_data = {
            'Finding ID': ['F-001', 'F-002', 'F-003', 'F-004'],
            'Audit': ['SOX 2023', 'PCI 2023', 'ISO 2023', 'SOX 2023'],
            'Severity': ['High', 'Medium', 'Low', 'Medium'],
            'Status': ['Remediated', 'In Progress', 'Open', 'Closed'],
            'Due Date': ['2024-01-15', '2024-02-28', '2024-03-15', '2024-01-30']
        }
        
        df_findings = pd.DataFrame(findings_data)
        
        # Color code by severity
        def highlight_severity(val):
            if val == 'High':
                return 'background-color: #fecaca'
            elif val == 'Medium':
                return 'background-color: #fef3c7'
            elif val == 'Low':
                return 'background-color: #d1fae5'
            return ''
        
        styled_df = df_findings.style.applymap(highlight_severity, subset=['Severity'])
        st.dataframe(styled_df, use_container_width=True)
    
    with tabs[3]:
        st.subheader("Compliance Dashboard & Reporting")
        
        # Compliance scorecard
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Overall Compliance Score", "94.2%", "↑ 1.8%")
        with col2:
            st.metric("Controls Testing Rate", "96.8%", "↑ 2.1%")
        with col3:
            st.metric("Audit Findings", "4", "↓ 2")
        
        # Compliance trend
        dates = pd.date_range(start='2023-01-01', end='2024-01-01', freq='M')
        compliance_scores = np.random.randint(90, 98, len(dates))
        
        fig_compliance = go.Figure()
        fig_compliance.add_trace(go.Scatter(x=dates, y=compliance_scores, mode='lines+markers', name='Compliance Score'))
        fig_compliance.update_layout(
            title="Compliance Score Trend",
            xaxis_title="Date",
            yaxis_title="Compliance Score (%)",
            yaxis=dict(range=[85, 100])
        )
        st.plotly_chart(fig_compliance, use_container_width=True)

# Advanced Threat Intelligence Integration
def create_threat_intelligence_module():
    st.header("🔍 Threat Intelligence & Analytics")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("analyze"):
        st.error("Access Denied: Analysis privileges required")
        return
    
    tabs = st.tabs(["Threat Landscape", "IOC Management", "Threat Hunting", "Intelligence Feeds"])
    
    with tabs[0]:
        st.subheader("Current Threat Landscape")
        
        # Threat level indicator
        threat_level = st.selectbox("Current Threat Level", 
                                  ["GREEN - Low", "YELLOW - Elevated", "ORANGE - High", "RED - Critical"])
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Active Threats", "127", "↑ 12")
        with col2:
            st.metric("Blocked Attacks", "2,341", "↑ 234")
        with col3:
            st.metric("False Positives", "45", "↓ 8")
        with col4:
            st.metric("MTTR", "23 min", "↓ 5 min")
        
        # Threat categories breakdown
        threat_categories = {
            'Category': ['Malware', 'Phishing', 'Insider Threat', 'APT', 'Ransomware', 'Supply Chain'],
            'Count': [45, 32, 8, 12, 15, 6],
            'Severity': [7.2, 8.1, 9.0, 9.5, 9.8, 8.7]
        }
        
        fig_threats = make_subplots(rows=1, cols=2, subplot_titles=('Threat Count by Category', 'Average Severity Score'))
        
        fig_threats.add_trace(
            go.Bar(x=threat_categories['Category'], y=threat_categories['Count'], name='Count'),
            row=1, col=1
        )
        
        fig_threats.add_trace(
            go.Scatter(x=threat_categories['Category'], y=threat_categories['Severity'], 
                      mode='lines+markers', name='Severity'),
            row=1, col=2
        )
        
        st.plotly_chart(fig_threats, use_container_width=True)
    
    with tabs[1]:
        st.subheader("Indicators of Compromise (IOC) Management")
        
        # IOC entry form
        with st.expander("Add New IOC"):
            col1, col2 = st.columns(2)
            with col1:
                ioc_type = st.selectbox("IOC Type", ["IP Address", "Domain", "File Hash", "URL", "Email"])
                ioc_value = st.text_input("IOC Value")
                threat_actor = st.text_input("Associated Threat Actor")
            with col2:
                confidence = st.selectbox("Confidence Level", ["Low", "Medium", "High"])
                severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"])
                expiry_date = st.date_input("Expiry Date")
        
        # IOC database
        ioc_data = [
            {"Type": "IP", "Value": "192.168.1.100", "Actor": "APT29", "Confidence": "High", "Severity": "Critical", "Added": "2024-01-10"},
            {"Type": "Domain", "Value": "malicious.com", "Actor": "Lazarus", "Confidence": "Medium", "Severity": "High", "Added": "2024-01-12"},
            {"Type": "Hash", "Value": "d41d8cd98f00b204e9800998ecf8427e", "Actor": "Unknown", "Confidence": "Low", "Severity": "Medium", "Added": "2024-01-14"}
        ]
        
        df_ioc = pd.DataFrame(ioc_data)
        st.dataframe(df_ioc, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Threat Hunting Dashboard")
        
        # Hunting queries
        hunting_queries = [
            "Unusual authentication patterns from privileged accounts",
            "Suspicious network connections to known bad IPs",
            "Anomalous data access patterns",
            "Unexpected system process executions",
            "Lateral movement indicators"
        ]
        
        selected_query = st.selectbox("Select Hunting Query", hunting_queries)
        
        if st.button("Execute Hunt"):
            # Simulate hunting results
            results = {
                "Total Events": 15632,
                "Suspicious Events": 23,
                "High Priority Alerts": 3,
                "Investigation Required": 1
            }
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Events", results["Total Events"])
            with col2:
                st.metric("Suspicious Events", results["Suspicious Events"])
            with col3:
                st.metric("High Priority", results["High Priority Alerts"])
            with col4:
                st.metric("Investigate", results["Investigation Required"])
    
    with tabs[3]:
        st.subheader("Intelligence Feed Management")
        
        # Intelligence feeds status
        feeds = [
            {"Feed": "Microsoft Threat Intelligence", "Status": "Active", "Last Update": "2024-01-15 09:30", "Records": 12543},
            {"Feed": "FBI IC3", "Status": "Active", "Last Update": "2024-01-15 08:45", "Records": 8721},
            {"Feed": "CISA Known Exploited Vulnerabilities", "Status": "Active", "Last Update": "2024-01-15 07:15", "Records": 967},
            {"Feed": "Commercial Threat Feed", "Status": "Active", "Last Update": "2024-01-15 06:00", "Records": 45123}
        ]
        
        df_feeds = pd.DataFrame(feeds)
        st.dataframe(df_feeds, use_container_width=True)

# Enterprise Security Metrics & KPIs
def create_metrics_dashboard():
    st.header("📊 Security Metrics & KPIs")
    
    tabs = st.tabs(["Executive KPIs", "Operational Metrics", "Cost Analysis", "Benchmark Comparison"])
    
    with tabs[0]:
        st.subheader("Executive Security KPIs")
        
        # Key performance indicators
        kpi_data = {
            "Metric": ["Mean Time to Detection (MTTD)", "Mean Time to Response (MTTR)", "Security ROI", 
                      "Employee Security Training Completion", "Vendor Risk Assessment Coverage"],
            "Current": ["4.2 hours", "23 minutes", "315%", "96.8%", "89.2%"],
            "Target": ["2 hours", "15 minutes", "300%", "100%", "95%"],
            "Trend": ["↓", "↓", "↑", "↑", "↑"],
            "Status": ["At Risk", "On Track", "Exceeding", "On Track", "On Track"]
        }
        
        df_kpis = pd.DataFrame(kpi_data)
        
        # Style the dataframe
        def color_status(val):
            if val == "Exceeding":
                return 'background-color: #d1fae5'
            elif val == "On Track":
                return 'background-color: #dbeafe'
            elif val == "At Risk":
                return 'background-color: #fecaca'
            return ''
        
        styled_kpis = df_kpis.style.applymap(color_status, subset=['Status'])
        st.dataframe(styled_kpis, use_container_width=True)
        
        # KPI trend visualization
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
        mttd_values = [6.1, 5.8, 5.2, 4.9, 4.5, 4.2]
        mttr_values = [35, 32, 28, 26, 24, 23]
        
        fig_kpi = make_subplots(
            rows=1, cols=2,
            subplot_titles=('MTTD Trend (Hours)', 'MTTR Trend (Minutes)'),
            specs=[[{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        fig_kpi.add_trace(
            go.Scatter(x=months, y=mttd_values, mode='lines+markers', name='MTTD'),
            row=1, col=1
        )
        
        fig_kpi.add_trace(
            go.Scatter(x=months, y=mttr_values, mode='lines+markers', name='MTTR', line=dict(color='red')),
            row=1, col=2
        )
        
        st.plotly_chart(fig_kpi, use_container_width=True)
    
    with tabs[1]:
        st.subheader("Operational Security Metrics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Security events by type
            event_types = ['Login Attempts', 'Malware Detected', 'Policy Violations', 'Data Access', 'Network Anomalies']
            event_counts = [15234, 432, 1876, 8921, 567]
            
            fig_events = go.Figure(data=[go.Pie(labels=event_types, values=event_counts)])
            fig_events.update_layout(title="Security Events by Type (Last 30 Days)")
            st.plotly_chart(fig_events, use_container_width=True)
        
        with col2:
            # Vulnerability metrics
            vuln_severity = ['Critical', 'High', 'Medium', 'Low']
            vuln_counts = [12, 45, 234, 567]
            
            fig_vulns = go.Figure(data=[go.Bar(x=vuln_severity, y=vuln_counts, 
                                             marker_color=['red', 'orange', 'yellow', 'green'])])
            fig_vulns.update_layout(title="Open Vulnerabilities by Severity")
            st.plotly_chart(fig_vulns, use_container_width=True)
        
        # Security training metrics
        st.subheader("Security Awareness Training Metrics")
        
        training_data = {
            'Department': ['Finance', 'HR', 'IT', 'Operations', 'Legal', 'Marketing', 'R&D'],
            'Completion_Rate': [98.5, 96.2, 99.1, 94.8, 97.3, 93.7, 95.6],
            'Phishing_Test_Score': [92, 88, 95, 85, 90, 82, 87]
        }
        
        fig_training = go.Figure()
        fig_training.add_trace(go.Bar(
            name='Training Completion %',
            x=training_data['Department'],
            y=training_data['Completion_Rate'],
            yaxis='y',
            offsetgroup=1
        ))
        fig_training.add_trace(go.Bar(
            name='Phishing Test Score %',
            x=training_data['Department'],
            y=training_data['Phishing_Test_Score'],
            yaxis='y',
            offsetgroup=2
        ))
        
        fig_training.update_layout(
            title="Security Training Metrics by Department",
            xaxis_title="Department",
            yaxis_title="Percentage",
            barmode='group'
        )
        st.plotly_chart(fig_training, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Security Investment & Cost Analysis")
        
        # Budget allocation and spending
        budget_categories = ['Personnel', 'Technology/Tools', 'Training', 'Consulting', 'Infrastructure', 'Compliance']
        allocated = [12.5, 8.3, 1.2, 2.1, 3.4, 1.5]
        spent = [11.8, 7.9, 1.0, 1.9, 3.2, 1.3]
        
        fig_budget = go.Figure()
        fig_budget.add_trace(go.Bar(name='Allocated ($M)', x=budget_categories, y=allocated))
        fig_budget.add_trace(go.Bar(name='Spent ($M)', x=budget_categories, y=spent))
        
        fig_budget.update_layout(
            title="Security Budget: Allocated vs Spent",
            xaxis_title="Category",
            yaxis_title="Amount ($ Millions)",
            barmode='group'
        )
        st.plotly_chart(fig_budget, use_container_width=True)
        
        # Cost per incident analysis
        st.subheader("Security Incident Cost Analysis")
        
        incident_costs = {
            'Incident Type': ['Data Breach', 'Malware', 'Insider Threat', 'DDoS Attack', 'Phishing'],
            'Average Cost': [4.35, 1.85, 2.79, 0.54, 0.98],
            'Frequency': [2, 15, 4, 8, 45],
            'Total Annual Cost': [8.7, 27.75, 11.16, 4.32, 44.1]
        }
        
        df_costs = pd.DataFrame(incident_costs)
        st.dataframe(df_costs, use_container_width=True)
    
    with tabs[3]:
        st.subheader("Industry Benchmark Comparison")
        
        # Benchmark data
        benchmark_data = {
            'Metric': ['Security Budget as % of IT Budget', 'MTTD (Hours)', 'MTTR (Minutes)', 
                      'Security Staff per 1000 Employees', 'Successful Phishing Rate'],
            'Our Company': [12.5, 4.2, 23, 2.3, 3.2],
            'Industry Average': [10.8, 6.5, 35, 1.8, 4.8],
            'Industry Leader': [15.2, 2.1, 12, 3.1, 1.2],
            'Performance': ['Above Average', 'Above Average', 'Above Average', 'Above Average', 'Above Average']
        }
        
        df_benchmark = pd.DataFrame(benchmark_data)
        st.dataframe(df_benchmark, use_container_width=True)
        
        # Radar chart for benchmark comparison
        metrics = benchmark_data['Metric']
        our_scores = [85, 90, 88, 92, 87]  # Normalized scores
        industry_avg = [70, 75, 72, 68, 70]
        industry_leader = [95, 98, 95, 96, 98]
        
        fig_radar = go.Figure()
        
        fig_radar.add_trace(go.Scatterpolar(
            r=our_scores,
            theta=metrics,
            fill='toself',
            name='Our Company'
        ))
        
        fig_radar.add_trace(go.Scatterpolar(
            r=industry_avg,
            theta=metrics,
            fill='toself',
            name='Industry Average'
        ))
        
        fig_radar.add_trace(go.Scatterpolar(
            r=industry_leader,
            theta=metrics,
            fill='toself',
            name='Industry Leader'
        ))
        
        fig_radar.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100]
                )),
            showlegend=True,
            title="Security Performance Benchmark Comparison"
        )
        
        st.plotly_chart(fig_radar, use_container_width=True)

# System Integration Management
def create_integration_module():
    st.header("🔗 Enterprise System Integrations")
    
    auth = EnterpriseAuth()
    if not auth.check_permission("admin"):
        st.error("Access Denied: Administrative privileges required")
        return
    
    tabs = st.tabs(["Integration Status", "API Management", "Data Flows", "Monitoring"])
    
    with tabs[0]:
        st.subheader("Enterprise Security Tool Integration Status")
        
        integrations = EnterpriseIntegrations()
        
        # Integration health dashboard
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Connected Systems", "7/8", "87.5%")
        with col2:
            st.metric("Data Sync Success Rate", "99.2%", "↑ 0.3%")
        with col3:
            st.metric("API Response Time", "156ms", "↓ 12ms")
        
        # Integration status table
        integration_status = []
        for system, details in integrations.integrations.items():
            status_color = "🟢" if details["status"] == "Connected" else "🔴"
            integration_status.append({
                "System": system,
                "Status": f"{status_color} {details['status']}",
                "Last Sync": details["last_sync"],
                "Health": "Healthy" if details["status"] == "Connected" else "Unhealthy"
            })
        
        df_integrations = pd.DataFrame(integration_status)
        st.dataframe(df_integrations, use_container_width=True)
        
        # Integration health visualization
        systems = list(integrations.integrations.keys())
        health_scores = np.random.randint(85, 100, len(systems))  # Mock health scores
        
        fig_health = go.Figure(data=[go.Bar(x=systems, y=health_scores, 
                                          marker_color=['green' if score > 95 else 'orange' if score > 90 else 'red' 
                                                       for score in health_scores])])
        fig_health.update_layout(
            title="Integration Health Scores",
            xaxis_title="Systems",
            yaxis_title="Health Score (%)",
            yaxis=dict(range=[80, 100])
        )
        st.plotly_chart(fig_health, use_container_width=True)
    
    with tabs[1]:
        st.subheader("API Management & Security")
        
        # API endpoint management
        api_endpoints = [
            {"Endpoint": "/api/v1/risks", "Method": "GET/POST", "Rate Limit": "1000/hour", "Authentication": "OAuth 2.0", "Status": "Active"},
            {"Endpoint": "/api/v1/controls", "Method": "GET/PUT", "Rate Limit": "500/hour", "Authentication": "API Key", "Status": "Active"},
            {"Endpoint": "/api/v1/incidents", "Method": "GET/POST", "Rate Limit": "200/hour", "Authentication": "JWT", "Status": "Active"},
            {"Endpoint": "/api/v1/compliance", "Method": "GET", "Rate Limit": "100/hour", "Authentication": "OAuth 2.0", "Status": "Active"}
        ]
        
        df_apis = pd.DataFrame(api_endpoints)
        st.dataframe(df_apis, use_container_width=True)
        
        # API usage analytics
        st.subheader("API Usage Analytics")
        
        api_names = ['Risk API', 'Control API', 'Incident API', 'Compliance API']
        requests_per_hour = [450, 320, 180, 85]
        error_rates = [0.1, 0.3, 0.2, 0.05]
        
        fig_api = make_subplots(
            rows=1, cols=2,
            subplot_titles=('API Requests per Hour', 'API Error Rates (%)'),
            specs=[[{"secondary_y": False}, {"secondary_y": False}]]
        )
        
        fig_api.add_trace(
            go.Bar(x=api_names, y=requests_per_hour, name='Requests/Hour'),
            row=1, col=1
        )
        
        fig_api.add_trace(
            go.Scatter(x=api_names, y=error_rates, mode='lines+markers', name='Error Rate %'),
            row=1, col=2
        )
        
        st.plotly_chart(fig_api, use_container_width=True)
    
    with tabs[2]:
        st.subheader("Security Data Flow Architecture")
        
        # Data flow diagram
        st.markdown("""
        ### Enterprise Security Data Flow
        
        ```
        External Threat Feeds → SIEM Platform → Risk Engine → Executive Dashboard
                ↓                    ↓             ↓              ↓
        Vulnerability Scanners → Asset Inventory → Control Assessment → Compliance Reports
                ↓                    ↓             ↓              ↓
        Identity Systems → Access Analytics → Risk Scoring → Automated Response
        ```
        """)
        
        # Data volume metrics
        data_flows = {
            'Source System': ['SIEM', 'Vulnerability Scanner', 'Identity Provider', 'Threat Intel', 'Asset Management'],
            'Daily Volume (GB)': [125.3, 45.7, 23.1, 12.8, 8.4],
            'Processing Time (min)': [15, 45, 5, 30, 20],
            'Data Quality Score': [98.5, 96.2, 99.1, 94.8, 97.3]
        }
        
        df_flows = pd.DataFrame(data_flows)
        st.dataframe(df_flows, use_container_width=True)
    
    with tabs[3]:
        st.subheader("Integration Monitoring & Alerting")
        
        # Monitoring alerts
        recent_alerts = [
            {"Time": "2024-01-15 09:45", "System": "Splunk", "Alert": "High log ingestion delay", "Severity": "Warning", "Status": "Investigating"},
            {"Time": "2024-01-15 08:30", "System": "ServiceNow", "Alert": "API rate limit exceeded", "Severity": "Critical", "Status": "Resolved"},
            {"Time": "2024-01-15 07:15", "System": "Qualys", "Alert": "Scan completion timeout", "Severity": "Warning", "Status": "Acknowledged"}
        ]
        
        df_alerts = pd.DataFrame(recent_alerts)
        
        # Color code by severity
        def highlight_severity(val):
            if val == 'Critical':
                return 'background-color: #fecaca'
            elif val == 'Warning':
                return 'background-color: #fef3c7'
            return ''
        
        styled_alerts = df_alerts.style.applymap(highlight_severity, subset=['Severity'])
        st.dataframe(styled_alerts, use_container_width=True)
        
        # System uptime monitoring
        st.subheader("System Uptime Monitoring")
        
        uptime_data = {
            'System': ['SIEM', 'GRC Platform', 'Vulnerability Scanner', 'SOAR', 'Identity Provider'],
            'Current Uptime': ['99.95%', '99.8%', '98.2%', '99.1%', '99.99%'],
            'Monthly SLA': ['99.9%', '99.5%', '99.0%', '99.0%', '99.95%'],
            'Status': ['✅ Meeting SLA', '✅ Meeting SLA', '⚠️ Below SLA', '✅ Meeting SLA', '✅ Meeting SLA']
        }
        
        df_uptime = pd.DataFrame(uptime_data)
        st.dataframe(df_uptime, use_container_width=True)

# Main application with enterprise navigation
def main():
    # Initialize session state for authentication
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.user_role = None
        st.session_state.username = None
    
    # Authentication UI
    if not st.session_state.authenticated:
        st.title("🛡️ Enterprise Security Architecture Platform")
        st.subheader("Please authenticate to continue")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            username = st.text_input("Username")
            role = st.selectbox("Role", ["CISO", "Security_Architect", "Security_Manager", "Security_Analyst", "Auditor", "Executive"])
            
            if st.button("Login", type="primary"):
                # Mock authentication - in production, integrate with enterprise SSO
                st.session_state.authenticated = True
                st.session_state.user_role = role
                st.session_state.username = username
                st.rerun()
        return
    
    # Main application interface
    st.sidebar.title(f"👤 {st.session_state.username}")
    st.sidebar.write(f"Role: {st.session_state.user_role}")
    
    if st.sidebar.button("Logout"):
        st.session_state.authenticated = False
        st.rerun()
    
    # Navigation based on role
    navigation_options = {
        "CISO": ["Executive Dashboard", "Risk Management", "Compliance", "Metrics & KPIs", "System Integrations", "SABSA Framework"],
        "Security_Architect": ["SABSA Framework", "Risk Management", "System Integrations", "Threat Intelligence", "Metrics & KPIs"],
        "Security_Manager": ["Risk Management", "Compliance", "Metrics & KPIs", "Threat Intelligence", "SABSA Framework"],
        "Security_Analyst": ["Threat Intelligence", "Risk Management", "SABSA Framework", "Metrics & KPIs"],
        "Auditor": ["Compliance", "Risk Management", "Metrics & KPIs", "SABSA Framework"],
        "Executive": ["Executive Dashboard", "Metrics & KPIs", "Risk Management"]
    }
    
    available_options = navigation_options.get(st.session_state.user_role, ["SABSA Framework"])
    selected_page = st.sidebar.selectbox("Navigation", available_options)
    
    # Page routing
    if selected_page == "Executive Dashboard":
        create_executive_dashboard()
    elif selected_page == "Risk Management":
        create_risk_management_module()
    elif selected_page == "Compliance":
        create_compliance_module()
    elif selected_page == "Threat Intelligence":
        create_threat_intelligence_module()
    elif selected_page == "Metrics & KPIs":
        create_metrics_dashboard()
    elif selected_page == "System Integrations":
        create_integration_module()
    elif selected_page == "SABSA Framework":
        # Original SABSA framework (simplified version for space)
        st.header("🔒 SABSA Security Architecture Framework")
        st.info("Interactive SABSA framework visualization and analysis tools")
        # Include original framework code here...
    
    # Global alerts and notifications
    st.sidebar.markdown("---")
    st.sidebar.subheader("🚨 Security Alerts")
    
    alerts = [
        {"type": "critical", "message": "3 critical vulnerabilities require immediate attention"},
        {"type": "warning", "message": "Compliance audit scheduled for next week"},
        {"type": "info", "message": "Security awareness training completion: 96.8%"}
    ]
    
    for alert in alerts:
        if alert["type"] == "critical":
            st.sidebar.error(alert["message"])
        elif alert["type"] == "warning":
            st.sidebar.warning(alert["message"])
        else:
            st.sidebar.info(alert["message"])

if __name__ == "__main__":
    main()
