import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import numpy as np
import json
import uuid
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Enhanced SABSA Security Architecture Framework",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS with animations and modern styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1e3a8a;
        text-align: center;
        margin-bottom: 1.5rem;
        animation: fadeIn 1s ease-in;
    }
    .node-card {
        background-color: #ffffff;
        border: 2px solid #3b82f6;
        border-radius: 10px;
        padding: 12px;
        margin: 6px;
        text-align: center;
        font-size: 14px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .node-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    .layer-header {
        background: linear-gradient(90deg, #1e3a8a, #3b82f6);
        color: white;
        padding: 12px;
        border-radius: 8px;
        text-align: center;
        font-weight: 600;
        margin: 12px 0;
        animation: slideIn 0.5s ease-out;
    }
    .process-node {
        background-color: #eff6ff;
        border: 2px solid #60a5fa;
        border-radius: 50%;
        width: 90px;
        height: 90px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 11px;
        text-align: center;
        transition: transform 0.2s;
    }
    .process-node:hover {
        transform: scale(1.1);
    }
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    @keyframes slideIn {
        from { transform: translateX(-20px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    .stButton>button {
        background: #1e3a8a;
        color: white;
        border-radius: 8px;
        padding: 8px 16px;
    }
    .stButton>button:hover {
        background: #2563eb;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for data persistence
if 'framework_data' not in st.session_state:
    st.session_state.framework_data = {
        "main_domains": {
            "Data Security": {"x": 1, "y": 5, "color": "#1e40af"},
            "Identity & Access Management": {"x": 3, "y": 5, "color": "#1e40af"},
            "Incident Handling & Response": {"x": 5, "y": 5, "color": "#1e40af"},
            "Vulnerability Management": {"x": 7, "y": 5, "color": "#1e40af"},
            "Security Risk Management": {"x": 9, "y": 5, "color": "#1e40af"}
        },
        "secondary_nodes": {
            "Data Devaluation": {"x": 0.5, "y": 4, "color": "#3b82f6", "parent": "Data Security"},
            "Data Integrity": {"x": 1, "y": 4, "color": "#3b82f6", "parent": "Data Security"},
            "Data Confidentiality": {"x": 1.5, "y": 4, "color": "#3b82f6", "parent": "Data Security"},
            "Security Testing": {"x": 1, "y": 3, "color": "#3b82f6", "parent": "Data Security"},
            "Authentication": {"x": 2.5, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management"},
            "Authorization": {"x": 3, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management"},
            "Access Recertification": {"x": 3.5, "y": 4, "color": "#3b82f6", "parent": "Identity & Access Management"},
            "Vulnerability Identification": {"x": 3, "y": 3, "color": "#3b82f6", "parent": "Identity & Access Management"},
            "Remediation Management": {"x": 4.5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response"},
            "Preparation": {"x": 5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response"},
            "Recovery": {"x": 5.5, "y": 4, "color": "#3b82f6", "parent": "Incident Handling & Response"},
            "Incident Communication": {"x": 5, "y": 3, "color": "#3b82f6", "parent": "Incident Handling & Response"},
            "Strategic Planning": {"x": 6.5, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management"},
            "Change Management": {"x": 7, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management"},
            "Security Risk Integration": {"x": 7.5, "y": 4, "color": "#3b82f6", "parent": "Vulnerability Management"},
            "Governance & Reporting": {"x": 8.5, "y": 4, "color": "#3b82f6", "parent": "Security Risk Management"},
            "Security Services Management": {"x": 9, "y": 4, "color": "#3b82f6", "parent": "Security Risk Management"}
        },
        "process_nodes": {
            "Encryption": {"x": 0.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Masking": {"x": 1, "y": 2, "color": "#60a5fa", "type": "process"},
            "Anonymization": {"x": 1.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Disclosure Authorization": {"x": 2, "y": 2, "color": "#60a5fa", "type": "process"},
            "Validation": {"x": 2.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Digital Signing": {"x": 3, "y": 2, "color": "#60a5fa", "type": "process"},
            "Multi-factor Authentication": {"x": 3.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Vulnerability Analysis": {"x": 4, "y": 2, "color": "#60a5fa", "type": "process"},
            "Estimation of Extend": {"x": 4.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Recovery Analysis": {"x": 5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Classification of Vulnerabilities and ...": {"x": 5.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Events History Repository": {"x": 6, "y": 2, "color": "#60a5fa", "type": "process"},
            "Wargaming": {"x": 6.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Maturity Frameworks": {"x": 7, "y": 2, "color": "#60a5fa", "type": "process"},
            "Incident Response Planning": {"x": 7.5, "y": 2, "color": "#60a5fa", "type": "process"},
            "Risk Appetite": {"x": 8, "y": 2, "color": "#60a5fa", "type": "process"},
            "Secure Repository": {"x": 0.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Inventory of Basic Accounts and...": {"x": 1, "y": 1, "color": "#60a5fa", "type": "process"},
            "Control of Privileged Access": {"x": 1.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Sandbox": {"x": 2, "y": 1, "color": "#60a5fa", "type": "process"},
            "Training": {"x": 2.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Role/Rule Management": {"x": 3, "y": 1, "color": "#60a5fa", "type": "process"},
            "Single Sign On": {"x": 3.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Remote Access Authentication": {"x": 4, "y": 1, "color": "#60a5fa", "type": "process"},
            "Monitoring and Qualification of...": {"x": 4.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Business Alignment": {"x": 5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Incident Escalation": {"x": 5.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Change Management": {"x": 6, "y": 1, "color": "#60a5fa", "type": "process"},
            "Metrics, KPIs, KRIs and MI": {"x": 6.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Secure Transition": {"x": 7, "y": 1, "color": "#60a5fa", "type": "process"},
            "Strategy": {"x": 7.5, "y": 1, "color": "#60a5fa", "type": "process"},
            "Security Testing Framework": {"x": 0.5, "y": 0, "color": "#60a5fa", "type": "process"},
            "Penetration Testing": {"x": 1, "y": 0, "color": "#60a5fa", "type": "process"},
            "Attestation": {"x": 1.5, "y": 0, "color": "#60a5fa", "type": "process"},
            "Automated testing": {"x": 2, "y": 0, "color": "#60a5fa", "type": "process"},
            "Recertification": {"x": 2.5, "y": 0, "color": "#60a5fa", "type": "process"},
            "Authenticated Scanning": {"x": 3, "y": 0, "color": "#60a5fa", "type": "process"},
            "Red Team Testing": {"x": 3.5, "y": 0, "color": "#60a5fa", "type": "process"},
            "Service Catalogue": {"x": 4, "y": 0, "color": "#60a5fa", "type": "process"},
            "Change Reconciliation": {"x": 4.5, "y": 0, "color": "#60a5fa", "type": "process"},
            "Case Management": {"x": 5, "y": 0, "color": "#60a5fa", "type": "process"}
        },
        "connections": [
            # Secondary node connections
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
            # Process connections
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

def create_interactive_framework():
    st.markdown('<h1 class="main-header">🔒 Enhanced SABSA Security Architecture Framework</h1>', unsafe_allow_html=True)
    
    # Load data
    data = get_framework_data()
    main_domains = data["main_domains"]
    secondary_nodes = data["secondary_nodes"]
    process_nodes = data["process_nodes"]
    connections = data["connections"]
    
    # Enhanced control panel
    st.sidebar.title("Framework Controls")
    view_mode = st.sidebar.radio("View Mode", ["Standard", "Edit Mode"], key="view_mode")
    show_connections = st.sidebar.checkbox("Show Connections", value=True)
    show_labels = st.sidebar.checkbox("Show Node Labels", value=True)
    highlight_domain = st.sidebar.selectbox("Highlight Domain", ["None"] + list(main_domains.keys()))
    zoom_level = st.sidebar.slider("Zoom Level", 0.5, 2.0, 1.0, 0.1)
    
    # Write mode interface
    if view_mode == "Edit Mode":
        with st.sidebar.expander("Add New Node", expanded=False):
            node_type = st.selectbox("Node Type", ["Main Domain", "Secondary Node", "Process Node"])
            node_name = st.text_input("Node Name")
            node_x = st.number_input("X Position", min_value=0.0, max_value=10.0, value=1.0, step=0.5)
            node_y = st.number_input("Y Position", min_value=0.0, max_value=5.0, value=1.0, step=0.5)
            parent_node = st.selectbox("Parent Node (for Secondary)", ["None"] + list(main_domains.keys())) if node_type == "Secondary Node" else None
            connect_to = st.multiselect("Connect to Existing Nodes", 
                                      list(main_domains.keys()) + list(secondary_nodes.keys()) + list(process_nodes.keys()))
            
            if st.button("Add Node"):
                if node_name:
                    node_id = str(uuid.uuid4())[:8]
                    color = "#1e40af" if node_type == "Main Domain" else "#3b82f6" if node_type == "Secondary Node" else "#60a5fa"
                    
                    if node_type == "Main Domain":
                        main_domains[node_name] = {"x": node_x, "y": node_y, "color": color}
                    elif node_type == "Secondary Node":
                        secondary_nodes[node_name] = {
                            "x": node_x, "y": node_y, "color": color, 
                            "parent": parent_node if parent_node != "None" else ""
                        }
                    else:
                        process_nodes[node_name] = {"x": node_x, "y": node_y, "color": color, "type": "process"}
                    
                    # Add connections
                    for target in connect_to:
                        connections.append((node_name, target))
                    
                    st.session_state.framework_data = {
                        "main_domains": main_domains,
                        "secondary_nodes": secondary_nodes,
                        "process_nodes": process_nodes,
                        "connections": connections
                    }
                    st.success(f"Added node: {node_name}")
    
    # Create the main visualization
    fig = go.Figure()
    
    # Add connections with animation
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
                    line=dict(color='rgba(100,100,100,0.4)', width=2, dash='dash'),
                    showlegend=False,
                    hoverinfo='none',
                    opacity=0.6
                ))
    
    # Add main domain nodes with enhanced styling
    main_x = [data["x"] for data in main_domains.values()]
    main_y = [data["y"] for data in main_domains.values()]
    main_names = list(main_domains.keys())
    main_colors = ['#ef4444' if name == highlight_domain else data["color"] for name, data in main_domains.items()]
    
    fig.add_trace(go.Scatter(
        x=main_x, y=main_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=70*zoom_level,
            color=main_colors,
            line=dict(width=2, color='white'),
            symbol='square'
        ),
        text=main_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=10*zoom_level, color='white', family="Arial Black"),
        name="Main Domains",
        hovertemplate='<b>%{text}</b><br>Domain Type: Main<extra></extra>'
    ))
    
    # Add secondary nodes with gradient colors
    sec_x = [data["x"] for data in secondary_nodes.values()]
    sec_y = [data["y"] for data in secondary_nodes.values()]
    sec_names = list(secondary_nodes.keys())
    sec_colors = ['#f87171' if highlight_domain != "None" and secondary_nodes[name]["parent"] == highlight_domain 
                 else data["color"] for name, data in secondary_nodes.items()]
    
    fig.add_trace(go.Scatter(
        x=sec_x, y=sec_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=50*zoom_level,
            color=sec_colors,
            line=dict(width=1.5, color='white'),
            symbol='diamond'
        ),
        text=sec_names if show_labels else None,
        textposition="middle center",
        textfont=dict(size=9*zoom_level, family="Arial"),
        name="Secondary Nodes",
        hovertemplate='<b>%{text}</b><br>Domain Type: Secondary<br>Parent: %{customdata}<extra></extra>',
        customdata=[secondary_nodes[name]["parent"] for name in sec_names]
    ))
    
    # Add process nodes with circular design
    proc_x = [data["x"] for data in process_nodes.values()]
    proc_y = [data["y"] for data in process_nodes.values()]
    proc_names = list(process_nodes.keys())
    proc_colors = [data["color"] for data in process_nodes.values()]
    
    fig.add_trace(go.Scatter(
        x=proc_x, y=proc_y,
        mode='markers+text' if show_labels else 'markers',
        marker=dict(
            size=35*zoom_level,
            color=proc_colors,
            line=dict(width=1.5, color='#4b5563'),
            symbol='circle'
        ),
        text=[name[:12] + '...' if len(name) > 12 else name for name in proc_names] if show_labels else None,
        textposition="middle center",
        textfont=dict(size=7*zoom_level, family="Arial"),
        name="Process Nodes",
        hovertemplate='<b>%{text}</b><br>Domain Type: Process<extra></extra>'
    ))
    
    # Enhanced layout with 3D effect
    fig.update_layout(
        title=dict(
            text="SABSA Security Architecture Framework - Interactive View",
            font=dict(size=20, color="#1e3a8a"),
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
        plot_bgcolor='rgba(219,234,254,0.9)',
        paper_bgcolor='white',
        height=800,
        showlegend=True,
        legend=dict(
            x=0.01,
            y=0.99,
            bgcolor='rgba(255,255,255,0.8)',
            bordercolor='#1e3a8a',
            borderwidth=1
        ),
        dragmode='pan',
        hovermode='closest',
        margin=dict(l=20, r=20, t=60, b=20)
    )
    
    # Display the chart with enhanced interactivity
    st.plotly_chart(fig, use_container_width=True, config={
        'displayModeBar': True,
        'modeBarButtonsToAdd': ['pan2d', 'zoomIn2d', 'zoomOut2d', 'resetScale2d', 'hoverClosest', 'hoverCompare'],
        'scrollZoom': True
    })
    
    return main_domains, secondary_nodes, process_nodes, connections

def show_detailed_view():
    st.header("Detailed Framework Analysis")
    
    main_domains, secondary_nodes, process_nodes, connections = create_interactive_framework()
    
    # Enhanced tabs with icons
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Domain Analysis",
        "🔗 Connection Matrix",
        "📋 Implementation Guide",
        "💾 Export Options"
    ])
    
    with tab1:
        st.subheader("Domain Breakdown")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Main Domains", len(main_domains), delta_color="normal")
        with col2:
            st.metric("Secondary Nodes", len(secondary_nodes), delta_color="normal")
        with col3:
            st.metric("Process Nodes", len(process_nodes), delta_color="normal")
        
        # Enhanced domain details table with sorting and filtering
        domain_data = []
        for domain in main_domains.keys():
            secondary_count = sum(1 for node in secondary_nodes.values() if node["parent"] == domain)
            domain_data.append({
                "Domain": domain,
                "Secondary Nodes": secondary_count,
                "Type": "Main",
                "Criticality": "High",
                "Connections": len([c for c in connections if domain in c])
            })
        
        for node, data in secondary_nodes.items():
            domain_data.append({
                "Domain": node,
                "Secondary Nodes": 0,
                "Type": "Secondary",
                "Criticality": "Medium",
                "Connections": len([c for c in connections if node in c])
            })
        
        for node in process_nodes.keys():
            domain_data.append({
                "Domain": node,
                "Secondary Nodes": 0,
                "Type": "Process",
                "Criticality": "Low",
                "Connections": len([c for c in connections if node in c])
            })
        
        df = pd.DataFrame(domain_data)
        st.dataframe(
            df,
            use_container_width=True,
            column_config={
                "Domain": st.column_config.TextColumn("Domain Name"),
                "Connections": st.column_config.NumberColumn("Connections", format="%d"),
                "Secondary Nodes": st.column_config.NumberColumn("Secondary Nodes", format="%d")
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
            height=700,
            xaxis=dict(tickangle=45),
            margin=dict(l=100, r=100, t=100, b=100)
        )
        
        st.plotly_chart(fig_matrix, use_container_width=True)
    
    with tab3:
        st.subheader("Implementation Guide")
        
        st.markdown("""
        ### Framework Implementation Steps:
        
        1. **Assess Current State**  
           - Map existing controls to framework nodes  
           - Identify coverage gaps using matrix analysis  
           - Evaluate connection strengths with metrics
        
        2. **Prioritize Implementation**  
           - Focus on main domains first  
           - Implement high-impact secondary nodes  
           - Deploy process nodes with automation
        
        3. **Establish Connections**  
           - Define data flows and integrations  
           - Implement API endpoints  
           - Monitor connection health with alerts
        
        4. **Continuous Improvement**  
           - Conduct regular framework reviews  
           - Update node relationships dynamically  
           - Optimize processes with AI-driven insights
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
        
        if st.button("Generate Framework JSON"):
            framework_export = {
                "main_domains": main_domains,
                "secondary_nodes": secondary_nodes,
                "process_nodes": process_nodes,
                "connections": connections,
                "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "version": "2.0"
            }
            
            st.json(framework_export)
            
            json_string = json.dumps(framework_export, indent=2)
            st.download_button(
                label="Download Framework Configuration",
                data=json_string,
                file_name="sabsa_framework.json",
                mime="application/json"
            )
        
        if st.button("Generate CSV Export"):
            export_data = []
            
            for domain, data in main_domains.items():
                export_data.append({
                    "Node": domain,
                    "Type": "Main Domain",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": "",
                    "Connections": len([c for c in connections if domain in c])
                })
            
            for node, data in secondary_nodes.items():
                export_data.append({
                    "Node": node,
                    "Type": "Secondary",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": data["parent"],
                    "Connections": len([c for c in connections if node in c])
                })
            
            for node, data in process_nodes.items():
                export_data.append({
                    "Node": node,
                    "Type": "Process",
                    "X": data["x"],
                    "Y": data["y"],
                    "Color": data["color"],
                    "Parent": "",
                    "Connections": len([c for c in connections if node in c])
                })
            
            export_df = pd.DataFrame(export_data)
            csv = export_df.to_csv(index=False)
            
            st.download_button(
                label="Download as CSV",
                data=csv,
                file_name="sabsa_framework.csv",
                mime="text/csv"
            )

def main():
    st.sidebar.title("SABSA Framework Navigation")
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
        The **Sherwood Applied Business Security Architecture (SABSA)** is a comprehensive methodology 
        for developing business-driven, risk-focused security architectures at enterprise and solution levels.
        
        ### Enhanced Features of this Tool:
        - **Interactive Visualization**: Dynamic, zoomable framework view with animations
        - **Edit Mode**: Add new nodes and connections with real-time updates
        - **Advanced Analytics**: Enhanced connection matrix and domain analysis
        - **Export Capabilities**: JSON and CSV exports with connection data
        - **Modern UI**: Improved styling with hover effects and gradients
        
        ### Framework Structure:
        - **Main Domains**: Core security domains
        - **Secondary Nodes**: Supporting capabilities
        - **Process Nodes**: Operational processes
        - **Connections**: Dynamic relationships
        
        This enhanced tool provides a modern, interactive interface for exploring and extending the SABSA framework.
        """)

if __name__ == "__main__":
    main()
