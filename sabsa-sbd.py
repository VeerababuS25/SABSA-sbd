import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
import numpy as np
import json
import uuid
from datetime import datetime

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
    .error-message {
        color: #dc2626;
        font-size: 12px;
        margin-top: 4px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for persistent data
if 'framework_data' not in st.session_state:
    st.session_state.framework_data = {
        "main_domains": {
            "Data Security": {"x": 1, "y": 5, "color": "#1e3a8a", "description": "Protects data assets"},
            "Identity & Access Management": {"x": 3, "y": 5, "color": "#1e3a8a", "description": "Controls access and identity"},
            "Incident Handling & Response": {"x": 5, "y": 5, "color": "#1e3a8a", "description": "Manages security incidents"},
            "Vulnerability Management": {"x": 7, "y": 5, "color": "#1e3a8a", "description": "Handles vulnerabilities"},
            "Security Risk Management": {"x": 9, "y": 5, "color": "#1e3a8a", "description": "Manages security risks"}
        },
        "secondary_nodes": {
            "Data Devaluation": {"x": 0.5, "y": 4, "color": "#3b82f6", "parent": "Data Security", "description": "Reduces data value exposure"},
            "Data Integrity": {"x": 1, "y": 4, "color": "#3b82f6", "parent": "Data Security", "description": "Ensures data accuracy"},
            "Data Confidentiality": {"x": 1.5, "y": 4, "color": "#3b82f6", "parent": "Data Security", "description": "Protects data privacy"},
            "Security Testing": {"x": 1, "y": 3, "color": "#3b82f6", "parent": "Data Security", "description": "Validates security controls"},
            "Authentication": {"x": 2.5, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Verifies user identity"},
            "Authorization": {"x": 3, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Controls access permissions"},
            "Access Recertification": {"x": 3.5, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Reviews access rights"},
            "Vulnerability Identification": {"x": 3, "y": 3, "color": "#3b82f6", "parent": "Identity & Access Management", "description": "Detects access vulnerabilities"},
            "Remediation Management": {"x": 4.5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Manages incident fixes"},
            "Preparation": {"x": 5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Prepares for incidents"},
            "Recovery": {"x": 5.5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Restores normal operations"},
            "Incident Communication": {"x": 5, "y": 3, "color": "#3b82f6", "parent": "Incident Handling & Response", "description": "Communicates incident details"},
            "Strategic Planning": {"x": 6.5, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management", "description": "Plans vulnerability strategy"},
            "Change Management": {"x": 7, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management", "description": "Manages security changes"},
            "Security Risk Integration": {"x": 7.5, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management", "description": "Integrates risk processes"},
            "Governance & Reporting": {"x": 8.5, "y": 4, "color": "#3b82f6", "parent": "Security Risk Management", "description": "Manages governance"},
            "Security Services Management": {"x": 9, "y": 4, "color": "#3b82f6", "parent": "Security Risk Management", "description": "Oversees security services"}
        },
        "process_nodes": {
            "Encryption": {"x": 0.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Secures data with encryption"},
            "Masking": {"x": 1, "y": 2, "color": "#60a5fa", "type": "process", "description": "Obfuscates sensitive data"},
            "Anonymization": {"x": 1.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Removes identifiable data"},
            "Disclosure Authorization": {"x": 2, "y": 2, "color": "#60a5fa", "type": "process", "description": "Controls data disclosure"},
            "Validation": {"x": 2.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Validates security controls"},
            "Digital Signing": {"x": 3, "y": 2, "color": "#60a5fa", "type": "process", "description": "Ensures data authenticity"},
            "Multi-factor Authentication": {"x": 3.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Enhances authentication"},
            "Vulnerability Analysis": {"x": 4, "y": 2, "color": "#60a5fa", "type": "process", "description": "Analyzes vulnerabilities"},
            "Estimation of Extend": {"x": 4.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Estimates vulnerability impact"},
            "Recovery Analysis": {"x": 5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Plans recovery strategies"},
            "Classification of Vulnerabilities": {"x": 5.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Categorizes vulnerabilities"},
            "Events History Repository": {"x": 6, "y": 2, "color": "#60a5fa", "type": "process", "description": "Stores event history"},
            "Wargaming": {"x": 6.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Simulates attack scenarios"},
            "Maturity Frameworks": {"x": 7, "y": 2, "color": "#60a5fa", "type": "process", "description": "Assesses maturity levels"},
            "Incident Response Planning": {"x": 7.5, "y": 2, "color": "#60a5fa", "type": "process", "description": "Plans incident response"},
            "Risk Appetite": {"x": 8, "y": 2, "color": "#60a5fa", "type": "process", "description": "Defines risk tolerance"},
            "Secure Repository": {"x": 0.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Secures data storage"},
            "Inventory of Basic Accounts": {"x": 1, "y": 1, "color": "#60a5fa", "type": "process", "description": "Tracks account inventory"},
            "Control of Privileged Access": {"x": 1.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Manages privileged access"},
            "Sandbox": {"x": 2, "y": 1, "color": "#60a5fa", "type": "process", "description": "Isolates testing environment"},
            "Training": {"x": 2.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Educates staff"},
            "Role/Rule Management": {"x": 3, "y": 1, "color": "#60a5fa", "type": "process", "description": "Manages access roles"},
            "Single Sign On": {"x": 3.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Simplifies authentication"},
            "Remote Access Authentication": {"x": 4, "y": 1, "color": "#60a5fa", "type": "process", "description": "Secures remote access"},
            "Monitoring and Qualification": {"x": 4.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Monitors security metrics"},
            "Business Alignment": {"x": 5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Aligns with business goals"},
            "Incident Escalation": {"x": 5.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Manages incident escalation"},
            "Change Management": {"x": 6, "y": 1, "color": "#60a5fa", "type": "process", "description": "Controls change processes"},
            "Metrics, KPIs, KRIs and MI": {"x": 6.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Tracks performance metrics"},
            "Secure Transition": {"x": 7, "y": 1, "color": "#60a5fa", "type": "process", "description": "Ensures secure transitions"},
            "Strategy": {"x": 7.5, "y": 1, "color": "#60a5fa", "type": "process", "description": "Defines security strategy"},
            "Security Testing Framework": {"x": 0.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Structures security tests"},
            "Penetration Testing": {"x": 1, "y": 0, "color": "#60a5fa", "type": "process", "description": "Simulates attacks"},
            "Attestation": {"x": 1.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Certifies compliance"},
            "Automated Testing": {"x": 2, "y": 0, "color": "#60a5fa", "type": "process", "description": "Automates security tests"},
            "Recertification": {"x": 2.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Renews certifications"},
            "Authenticated Scanning": {"x": 3, "y": 0, "color": "#60a5fa", "type": "process", "description": "Scans with authentication"},
            "Red Team Testing": {"x": 3.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Simulates advanced attacks"},
            "Service Catalogue": {"x": 4, "y": 0, "color": "#60a5fa", "type": "process", "description": "Lists security services"},
            "Change Reconciliation": {"x": 4.5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Reconciles changes"},
            "Case Management": {"x": 5, "y": 0, "color": "#60a5fa", "type": "process", "description": "Manages security cases"}
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

def validate_node_input(node_name, node_x, node_y, parent_node, node_type):
    """Validate node input before adding."""
    errors = []
    if not node_name or len(node_name.strip()) == 0:
        errors.append("Node name cannot be empty.")
    if node_name in {**st.session_state.framework_data["main_domains"], 
                     **st.session_state.framework_data["secondary_nodes"], 
                     **st.session_state.framework_data["process_nodes"]}:
        errors.append("Node name must be unique.")
    if node_x < 0 or node_x > 10 or node_y < 0 or node_y > 5:
        errors.append("Position coordinates must be within bounds (X: 0-10, Y: 0-5).")
    if node_type == "Secondary Node" and parent_node == "None":
        errors.append("Secondary nodes must have a parent domain.")
    return errors

def create_interactive_framework():
    st.markdown('<h1 class="main-header">🔒 Enterprise SABSA Security Architecture Framework</h1>', unsafe_allow_html=True)
    
    # Load data
    data = get_framework_data()
    main_domains = data["main_domains"]
    secondary_nodes = data["secondary_nodes"]
    process_nodes = data["process_nodes"]
    connections = data["connections"]
    
    # Professional control panel
    st.sidebar.title("Framework Controls")
    view_mode = st.sidebar.radio("Mode", ["View", "Management"], key="view_mode")
    show_connections = st.sidebar.checkbox("Show Connections", value=True)
    show_labels = st.sidebar.checkbox("Show Labels", value=True)
    highlight_domain = st.sidebar.selectbox("Highlight Domain", ["None"] + list(main_domains.keys()))
    node_opacity = st.sidebar.slider("Node Opacity", 0.5, 1.0, 0.8, 0.05)
    
    # Management mode
    if view_mode == "Management":
        with st.sidebar.expander("Manage Nodes", expanded=True):
            st.subheader("Add New Node")
            node_type = st.selectbox("Node Type", ["Main Domain", "Secondary Node", "Process Node"], key="node_type")
            node_name = st.text_input("Node Name", key="node_name")
            node_description = st.text_area("Description (Optional)", height=100)
            node_x = st.number_input("X Position", min_value=0.0, max_value=10.0, value=1.0, step=0.1, key="node_x")
            node_y = st.number_input("Y Position", min_value=0.0, max_value=5.0, value=1.0, step=0.1, key="node_y")
            parent_node = st.selectbox("Parent Domain (for Secondary)", ["None"] + list(main_domains.keys())) if node_type == "Secondary Node" else None
            connect_to = st.multiselect("Connect to Nodes", 
                                      list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()))
            
            if st.button("Add Node", key="add_node"):
                errors = validate_node_input(node_name, node_x, node_y, parent_node, node_type)
                if errors:
                    for error in errors:
                        st.markdown(f'<p class="error-message">{error}</p>', unsafe_allow_html=True)
                else:
                    node_id = str(uuid.uuid4())[:8]
                    color = "#1e3a8a" if node_type == "Main Domain" else "#3b82f6" if node_type == "Secondary Node" else "#60a5fa"
                    
                    if node_type == "Main Domain":
                        main_domains[node_name] = {"x": node_x, "y": node_y, "color": color, "description": node_description}
                    elif node_type == "Secondary Node":
                        secondary_nodes[node_name] = {
                            "x": node_x, "y": node_y, "color": color, 
                            "parent": parent_node if parent_node != "None" else "", 
                            "description": node_description
                        }
                    else:
                        process_nodes[node_name] = {
                            "x": node_x, "y": node_y, "color": color, 
                            "type": "process", "description": node_description
                        }
                    
                    for target in connect_to:
                        connections.append((node_name, target))
                    
                    st.session_state.framework_data = {
                        "main_domains": main_domains,
                        "secondary_nodes": secondary_nodes,
                        "process_nodes": process_nodes,
                        "connections": connections
                    }
                    st.success(f"Node '{node_name}' added successfully")
        
        with st.sidebar.expander("Delete Node", expanded=False):
            st.subheader("Remove Existing Node")
            node_to_delete = st.selectbox("Select Node to Delete", 
                                        list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()))
            if st.button("Delete Node", key="delete_node"):
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
                st.success(f"Node '{node_to_delete}' deleted successfully")
    
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
    
    fig.add_trace(go.Scatter(
        x=main_x, y=main_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=80,
            color=main_colors,
            line=dict(width=2, color='#ffffff'),
            symbol='square',
            opacity=node_opacity
        ),
        text=main_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=12, color='#ffffff', family="Inter"),
        name="Main Domains",
        hovertemplate='<b>%{text}</b><br>Type: Main Domain<br>Description: %{customdata}<extra></extra>',
        customdata=main_descriptions
    ))
    
    # Add secondary nodes
    sec_x = [data["x"] for data in secondary_nodes.values()]
    sec_y = [data["y"] for data in secondary_nodes.values()]
    sec_names = list(secondary_nodes.keys())
    sec_colors = ['#f87171' if highlight_domain != "None" and secondary_nodes[name]["parent"] == highlight_domain 
                 else data["color"] for name, data in secondary_nodes.items()]
    sec_parents = [data["parent"] for data in secondary_nodes.values()]
    sec_descriptions = [data.get("description", "") for data in secondary_nodes.values()]
    
    fig.add_trace(go.Scatter(
        x=sec_x, y=sec_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=60,
            color=sec_colors,
            line=dict(width=1.5, color='#ffffff'),
            symbol='diamond',
            opacity=node_opacity
        ),
        text=sec_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=10, family="Inter"),
        name="Secondary Nodes",
        hovertemplate='<b>%{text}</b><br>Type: Secondary<br>Parent: %{customdata[0]}<br>Description: %{customdata[1]}<extra></extra>',
        customdata=list(zip(sec_parents, sec_descriptions))
    ))
    
    # Add process nodes
    proc_x = [data["x"] for data in process_nodes.values()]
    proc_y = [data["y"] for data in process_nodes.values()]
    proc_names = list(process_nodes.keys())
    proc_colors = [data["color"] for data in process_nodes.values()]
    proc_descriptions = [data.get("description", "") for data in process_nodes.values()]
    
    fig.add_trace(go.Scatter(
        x=proc_x, y=proc_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=40,
            color=proc_colors,
            line=dict(width=1.5, color='#4b5563'),
            symbol='circle',
            opacity=node_opacity
        ),
        text=[name[:10] + '...' if len(name) > 10 else name for name in proc_names] if show_labels else None,
        textposition="middle center",
        textfont=dict(size=8, family="Inter"),
        name="Process Nodes",
        hovertemplate='<b>%{text}</b><br>Type: Process<br>Description: %{customdata}<extra></extra>',
        customdata=proc_descriptions
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
        height=850,
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
    
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Domain Analysis",
        "🔗 Connection Matrix",
        "📋 Implementation Guide",
        "💾 Export Options"
    ])
    
    with tab1:
        st.subheader("Domain Analysis")
        
        col1, col2, col3 = st.columns(3)
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
        
        domain_data = []
        for domain, data in main_domains.items():
            secondary_count = sum(1 for node in secondary_nodes.values() if node["parent"] == domain)
            domain_data.append({
                "Domain": domain,
                "Type": "Main",
                "Secondary Nodes": secondary_count,
                "Connections": len([c for c in connections if domain in c]),
                "Description": data.get("description", "")
            })
        
        for node, data in secondary_nodes.items():
            domain_data.append({
                "Domain": node,
                "Type": "Secondary",
                "Secondary Nodes": 0,
                "Connections": len([c for c in connections if node in c]),
                "Description": data.get("description", "")
            })
        
        for node, data in process_nodes.items():
            domain_data.append({
                "Domain": node,
                "Type": "Process",
                "Secondary Nodes": 0,
                "Connections": len([c for c in connections if node in c]),
                "Description": data.get("description", "")
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
                "Description": st.column_config.TextColumn("Description", width="large")
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
           - Benchmark against industry standards
        
        2. **Implementation Prioritization**  
           - Deploy critical main domains first  
           - Focus on high-impact secondary nodes  
           - Automate process node deployment
        
        3. **Integration Strategy**  
           - Establish API-driven integrations  
           - Define data flows between nodes  
           - Implement real-time monitoring
        
        4. **Continuous Optimization**  
           - Conduct quarterly framework reviews  
           - Update connections based on threats  
           - Leverage analytics for improvements
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
                "version": "3.0"
            }
            
            st.json(framework_export)
            
            json_string = json.dumps(framework_export, indent=2)
            st.download_button(
                label="Download JSON",
                data=json_string,
                file_name="sabsa_framework.json",
                mime="application/json"
            )
        
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
                    "Description": data.get("description", "")
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
                    "Description": data.get("description", "")
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
                    "Description": data.get("description", "")
                })
            
            export_df = pd.DataFrame(export_data)
            csv = export_df.to_csv(index=False)
            
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="sabsa_framework.csv",
                mime="text/csv"
            )

def main():
    st.sidebar.title("SABSA Framework")
    view_mode = st.sidebar.radio(
        "Select View",
        ["Interactive Framework", "Detailed Analysis", "About"],
        key="main_view_mode"
    )
    
    if view_mode == "Interactive Framework":
        create_interactive_framework()
    elif view_mode == "Detailed Analysis":
        show_detailed_view()
    elif view_mode == "About":
        st.header("About SABSA Framework")
        st.markdown("""
        The **Sherwood Applied Business Security Architecture (SABSA)** is an enterprise-grade methodology 
        for developing risk-driven security architectures aligned with business objectives.
        
        ### Enterprise Features:
        - **Professional Visualization**: Clean, interactive framework view with smooth animations
        - **Management Mode**: Add, delete, and connect nodes with validation
        - **Advanced Analytics**: Detailed domain analysis and connection matrix
        - **Export Capabilities**: Comprehensive JSON and CSV exports
        - **Modern UI**: Responsive design with enterprise-grade aesthetics
        
        ### Framework Structure:
        - **Main Domains**: Core security pillars
        - **Secondary Nodes**: Supporting capabilities
        - **Process Nodes**: Operational processes
        - **Connections**: Dynamic relationships
        
        This enterprise-grade tool provides a robust platform for managing and extending the SABSA framework.
        """)

if __name__ == "__main__":
    main()
